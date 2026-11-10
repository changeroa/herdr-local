//! Explicit, one-use identity bridge for exporters predating terminal IDs.
//! Never carries client ownership: surviving clients must prove it again.
use std::collections::{BTreeMap, HashSet};
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::RawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::handoff::HandoffManifest;
use crate::terminal::TerminalId;

const PATH_ENV: &str = "HERDR_HANDOFF_IDENTITY_BRIDGE";
const NONCE_ENV: &str = "HERDR_HANDOFF_IDENTITY_NONCE";
const MAX_AGE_SECONDS: u64 = 120;
const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ProcessProof {
    pid: u32,
    started_at: String,
}

impl ProcessProof {
    fn capture(pid: u32) -> io::Result<Self> {
        let started_at = crate::platform::process_started_at(pid)
            .ok_or_else(|| invalid("process generation unavailable"))?;
        Ok(Self { pid, started_at })
    }

    fn validate(&self) -> io::Result<()> {
        if self.pid == 0 || self.started_at.is_empty() || Self::capture(self.pid)? != *self {
            return Err(invalid("process generation changed"));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PaneIdentity {
    pane_id: String,
    terminal_id: TerminalId,
    shell: ProcessProof,
    foreground_group: u32,
    foreground: Vec<ProcessProof>,
}

#[derive(Serialize, Deserialize)]
struct IdentityBridge {
    version: u32,
    nonce: String,
    created_at: u64,
    source: ProcessProof,
    panes: Vec<PaneIdentity>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::other(format!("handoff identity: {message}"))
}

fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(io::Error::other)
}

fn request(method: &str, params: Value, source: &mut Option<ProcessProof>) -> io::Result<Value> {
    let mut stream = UnixStream::connect(crate::api::socket_path())?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let peer = ProcessProof::capture(crate::platform::local_socket_peer_pid(&stream)?)?;
    if source.as_ref().is_some_and(|old| old != &peer) {
        return Err(invalid("source server changed during preparation"));
    }
    *source = Some(peer);
    serde_json::to_writer(
        &mut stream,
        &json!({"id":"handoff:identity", "method":method,"params":params}),
    )?;
    stream.write_all(b"\n")?;
    let mut line = String::new();
    BufReader::new(stream)
        .take(MAX_BYTES)
        .read_line(&mut line)?;
    let response: Value = serde_json::from_str(&line)?;
    if response.get("error").is_some() {
        return Err(invalid("source API rejected identity preparation"));
    }
    Ok(response["result"].clone())
}

fn snapshot_identities(snapshot: &Value) -> io::Result<BTreeMap<String, TerminalId>> {
    let mut identities = BTreeMap::new();
    let mut terminals = HashSet::new();
    for pane in snapshot["panes"]
        .as_array()
        .ok_or_else(|| invalid("missing snapshot panes"))?
    {
        let pane_id = pane["pane_id"]
            .as_str()
            .ok_or_else(|| invalid("missing pane ID"))?;
        let terminal_id: TerminalId = serde_json::from_value(pane["terminal_id"].clone())?;
        if terminal_id.as_str().is_empty()
            || !terminals.insert(terminal_id.clone())
            || identities
                .insert(pane_id.to_string(), terminal_id)
                .is_some()
        {
            return Err(invalid("duplicate or empty identity"));
        }
    }
    Ok(identities)
}

/// Run with the candidate binary, against the old API, BEFORE requesting handoff.
/// The caller supplies an unguessable nonce and passes it only to the importer.
pub(crate) fn prepare(path: &Path, nonce: &str) -> io::Result<()> {
    if nonce.len() < 32 {
        return Err(invalid("nonce must contain at least 32 characters"));
    }
    let mut source = None;
    let snapshot = request("session.snapshot", json!({}), &mut source)?;
    let identities = snapshot_identities(&snapshot["snapshot"])?;
    let mut panes = Vec::new();
    for (pane_id, terminal_id) in &identities {
        let info = request("pane.process_info", json!({"pane_id":pane_id}), &mut source)?;
        let child_pid = info["process_info"]["shell_pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok())
            .ok_or_else(|| invalid("missing shell PID"))?;
        let shell = ProcessProof::capture(child_pid)?;
        let job = crate::platform::foreground_job_for_client_registration(child_pid)
            .ok_or_else(|| invalid("foreground job unavailable"))?;
        let mut foreground = Vec::new();
        for process in job.processes {
            foreground.push(ProcessProof::capture(process.pid)?);
        }
        if foreground.is_empty() {
            return Err(invalid("empty foreground proof"));
        }
        shell.validate()?;
        panes.push(PaneIdentity {
            pane_id: pane_id.clone(),
            terminal_id: terminal_id.clone(),
            shell,
            foreground_group: job.process_group_id,
            foreground,
        });
    }
    let snapshot = request("session.snapshot", json!({}), &mut source)?;
    if snapshot_identities(&snapshot["snapshot"])? != identities {
        return Err(invalid("pane identities changed during preparation"));
    }
    let bridge = IdentityBridge {
        version: 1,
        nonce: nonce.to_string(),
        created_at: now()?,
        source: source.ok_or_else(|| invalid("source unavailable"))?,
        panes,
    };
    bridge.source.validate()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    serde_json::to_writer(&mut file, &bridge)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn read_bridge() -> io::Result<IdentityBridge> {
    let path = std::env::var_os(PATH_ENV)
        .ok_or_else(|| invalid("legacy exporter requires an explicit prepared identity bridge"))?;
    let nonce = std::env::var(NONCE_ENV).map_err(|_| invalid("missing bridge nonce"))?;
    // Never leak migration input to restored children or a later handoff.
    std::env::remove_var(PATH_ENV);
    std::env::remove_var(NONCE_ENV);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_BYTES
    {
        return Err(invalid("bridge must be an owner-only regular file"));
    }
    let bridge: IdentityBridge = serde_json::from_reader(file.take(MAX_BYTES))?;
    validate_header(&bridge, &nonce, now()?)?;
    // Consume once, including attempts that subsequently fail validation.
    std::fs::remove_file(path)?;
    Ok(bridge)
}

fn validate_header(bridge: &IdentityBridge, nonce: &str, current_time: u64) -> io::Result<()> {
    if bridge.version != 1
        || nonce.len() < 32
        || bridge.nonce != nonce
        || current_time
            .checked_sub(bridge.created_at)
            .is_none_or(|age| age > MAX_AGE_SECONDS)
    {
        return Err(invalid("stale bridge or wrong nonce/version"));
    }
    Ok(())
}

fn public_panes(manifest: &HandoffManifest) -> io::Result<BTreeMap<u32, String>> {
    let mut panes = BTreeMap::new();
    for workspace in &manifest.snapshot.workspaces {
        let workspace_id = workspace
            .id
            .as_ref()
            .ok_or_else(|| invalid("missing workspace identity"))?;
        for tab in &workspace.tabs {
            for raw in tab.panes.keys() {
                let number = workspace
                    .public_pane_numbers
                    .get(raw)
                    .ok_or_else(|| invalid("missing public pane identity"))?;
                let public = format!(
                    "{workspace_id}:p{}",
                    crate::workspace::encode_public_number(*number)
                );
                if panes.insert(*raw, public).is_some() {
                    return Err(invalid("duplicate raw pane ID"));
                }
            }
        }
    }
    Ok(panes)
}

/// Called before acknowledging validation, so a rejected bridge rolls back the source.
pub(crate) fn complete_manifest(
    manifest: &mut HandoffManifest,
    stream: &UnixStream,
) -> io::Result<Option<Vec<PaneIdentity>>> {
    let missing = manifest
        .panes
        .iter()
        .filter(|pane| pane.terminal_id.is_none())
        .count();
    if missing == 0 {
        validate_terminal_ids(manifest)?;
        return Ok(None);
    }
    if missing != manifest.panes.len() {
        return Err(invalid("mixed legacy and identified runtimes"));
    }
    let bridge = read_bridge()?;
    if crate::platform::local_socket_peer_pid(stream)? != bridge.source.pid {
        return Err(invalid("bridge belongs to a different source server"));
    }
    bridge.source.validate()?;
    let proofs = apply_bridge(manifest, bridge.panes)?;
    for proof in &proofs {
        validate_processes(proof)?;
    }
    Ok(Some(proofs))
}

fn apply_bridge(
    manifest: &mut HandoffManifest,
    panes: Vec<PaneIdentity>,
) -> io::Result<Vec<PaneIdentity>> {
    let public = public_panes(manifest)?;
    if public.len() != manifest.panes.len() || panes.len() != public.len() {
        return Err(invalid("bridge pane membership changed"));
    }
    let mut identities: BTreeMap<_, _> = BTreeMap::new();
    for pane in panes {
        if identities.insert(pane.pane_id.clone(), pane).is_some() {
            return Err(invalid("duplicate bridge pane"));
        }
    }
    let mut proofs = Vec::new();
    let mut raw_ids = HashSet::new();
    for runtime in &mut manifest.panes {
        if !raw_ids.insert(runtime.pane_id) {
            return Err(invalid("duplicate runtime pane"));
        }
        let public_id = public
            .get(&runtime.pane_id)
            .ok_or_else(|| invalid("unknown runtime pane"))?;
        let identity = identities
            .remove(public_id)
            .ok_or_else(|| invalid("missing bridge pane"))?;
        if identity.shell.pid != runtime.child_pid {
            return Err(invalid("shell PID changed"));
        }
        runtime.terminal_id = Some(identity.terminal_id.clone());
        proofs.push(identity);
    }
    validate_terminal_ids(manifest)?;
    Ok(proofs)
}

fn validate_terminal_ids(manifest: &HandoffManifest) -> io::Result<()> {
    let mut ids = HashSet::new();
    for pane in &manifest.panes {
        let id = pane
            .terminal_id
            .as_ref()
            .ok_or_else(|| invalid("missing terminal ID"))?;
        if id.as_str().is_empty() || !ids.insert(id) {
            return Err(invalid("empty or duplicate terminal ID"));
        }
    }
    Ok(())
}

fn validate_processes(pane: &PaneIdentity) -> io::Result<()> {
    pane.shell.validate()?;
    let job = crate::platform::foreground_job_for_client_registration(pane.shell.pid)
        .ok_or_else(|| invalid("foreground job disappeared"))?;
    let actual: HashSet<_> = job.processes.iter().map(|p| p.pid).collect();
    let expected: HashSet<_> = pane.foreground.iter().map(|p| p.pid).collect();
    if actual.is_empty()
        || actual != expected
        || expected.len() != pane.foreground.len()
        || job.process_group_id != pane.foreground_group
    {
        return Err(invalid("foreground membership changed"));
    }
    for process in &pane.foreground {
        process.validate()?;
    }
    pane.shell.validate()
}

pub(crate) fn validate_fds(proofs: Option<&[PaneIdentity]>, fds: &[RawFd]) -> io::Result<()> {
    let Some(proofs) = proofs else {
        return Ok(());
    };
    if proofs.len() != fds.len() {
        return Err(invalid("PTY count changed"));
    }
    for (pane, fd) in proofs.iter().zip(fds) {
        validate_processes(pane)?;
        if crate::platform::foreground_process_group_id_for_tty_fd(*fd)
            != Some(pane.foreground_group)
        {
            return Err(invalid("imported PTY does not match foreground proof"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (HandoffManifest, Vec<PaneIdentity>) {
        let manifest = serde_json::from_value(json!({
            "version":1,"source_version":"0.8.2","source_protocol":20,
            "expected_version":null,"expected_protocol":null,
            "snapshot":{"version":3,"active":0,"selected":0,"workspaces":[{
                "id":"w1","identity_cwd":"/tmp","public_pane_numbers":{"7":9,"42":3},
                "tabs":[{"layout":{"Split":{"direction":"Horizontal","ratio":0.5,
                    "first":{"Pane":7},"second":{"Pane":42}}},
                    "panes":{"7":{"cwd":"/tmp"},"42":{"cwd":"/tmp"}},"zoomed":false}]
            }]},
            "panes":[
                {"pane_id":42,"child_pid":420,"rows":24,"cols":80,"cell_width_px":0,"cell_height_px":0},
                {"pane_id":7,"child_pid":70,"rows":24,"cols":80,"cell_width_px":0,"cell_height_px":0}
            ]
        })).unwrap();
        let panes = [("w1:p9", "term_first", 70), ("w1:p3", "term_second", 420)]
            .into_iter()
            .map(|(pane, terminal, pid)| PaneIdentity {
                pane_id: pane.into(),
                terminal_id: serde_json::from_value(json!(terminal)).unwrap(),
                shell: ProcessProof {
                    pid,
                    started_at: "generation".into(),
                },
                foreground_group: pid,
                foreground: vec![ProcessProof {
                    pid,
                    started_at: "generation".into(),
                }],
            })
            .collect();
        (manifest, panes)
    }

    #[test]
    fn handoff_identity_mapping_preserves_adversarial_workspace_invariants() {
        let state = crate::app::AppState::test_with_adversarial_identity_state();
        state.assert_invariants_for_test();
        let snapshot = crate::persist::capture(
            &state.workspaces,
            &state.terminals,
            &Default::default(),
            state.active,
            state.selected,
            state.sidebar_width,
            state.sidebar_section_split,
            state.collapsed_space_keys.clone(),
        );
        let mut runtimes = Vec::new();
        let mut proofs = Vec::new();
        let mut expected = BTreeMap::new();
        for workspace in &state.workspaces {
            for tab in &workspace.tabs {
                for (raw, pane) in &tab.panes {
                    let pid = raw.raw() + 100;
                    runtimes.push(
                        serde_json::from_value(json!({"pane_id":raw.raw(),
                        "child_pid":pid,"rows":24,"cols":80,"cell_width_px":0,"cell_height_px":0}))
                        .unwrap(),
                    );
                    proofs.push(PaneIdentity {
                        pane_id: crate::workspace::public_pane_id_for_number(
                            &workspace.id,
                            workspace.public_pane_number(*raw).unwrap(),
                        ),
                        terminal_id: pane.attached_terminal_id.clone(),
                        shell: ProcessProof {
                            pid,
                            started_at: "generation".into(),
                        },
                        foreground_group: pid,
                        foreground: Vec::new(),
                    });
                    expected.insert(raw.raw(), pane.attached_terminal_id.clone());
                }
            }
        }
        proofs.reverse();
        let mut manifest =
            super::super::handoff::manifest_for(snapshot, runtimes, None, None, None);
        apply_bridge(&mut manifest, proofs).unwrap();
        for runtime in manifest.panes {
            assert_eq!(runtime.terminal_id.as_ref(), expected.get(&runtime.pane_id));
        }
        state.assert_invariants_for_test();
    }

    #[test]
    fn legacy_handoff_maps_public_identity_to_runtime_order_without_allocating() {
        let (mut manifest, panes) = fixture();
        assert!(manifest.panes.iter().all(|pane| pane.terminal_id.is_none()));
        let proofs = apply_bridge(&mut manifest, panes).unwrap();
        assert_eq!(
            manifest.panes[0].terminal_id.as_ref().unwrap().as_str(),
            "term_second"
        );
        assert_eq!(
            manifest.panes[1].terminal_id.as_ref().unwrap().as_str(),
            "term_first"
        );
        assert_eq!(
            proofs.iter().map(|p| p.shell.pid).collect::<Vec<_>>(),
            [420, 70]
        );
        let roundtrip: HandoffManifest =
            serde_json::from_value(serde_json::to_value(&manifest).unwrap()).unwrap();
        validate_terminal_ids(&roundtrip).unwrap();
        assert_eq!(
            roundtrip.panes[0].terminal_id,
            manifest.panes[0].terminal_id
        );
    }

    #[test]
    fn legacy_handoff_rejects_missing_duplicate_and_mismatched_membership() {
        for corruption in 0..6 {
            let (mut manifest, mut panes) = fixture();
            match corruption {
                0 => {
                    panes.pop();
                }
                1 => {
                    panes[1].pane_id = panes[0].pane_id.clone();
                }
                2 => {
                    panes[1].terminal_id = panes[0].terminal_id.clone();
                }
                3 => {
                    panes[1].shell.pid += 1;
                }
                4 => {
                    panes[1].pane_id = "w2:p3".into();
                }
                5 => {
                    manifest.panes[1].pane_id = manifest.panes[0].pane_id;
                }
                _ => unreachable!(),
            }
            assert!(
                apply_bridge(&mut manifest, panes).is_err(),
                "corruption {corruption}"
            );
        }
    }

    #[test]
    fn identity_bridge_rejects_expired_future_and_wrong_nonce() {
        let (_, panes) = fixture();
        let nonce = "0123456789abcdef0123456789abcdef";
        let bridge = IdentityBridge {
            version: 1,
            nonce: nonce.into(),
            created_at: 1000,
            source: ProcessProof {
                pid: 1,
                started_at: "source".into(),
            },
            panes,
        };
        validate_header(&bridge, nonce, 1000).unwrap();
        assert!(validate_header(&bridge, nonce, 1121).is_err());
        assert!(validate_header(&bridge, nonce, 999).is_err());
        assert!(validate_header(&bridge, "fedcba9876543210fedcba9876543210", 1000).is_err());
    }

    #[test]
    fn handoff_process_generation_rejects_reused_or_missing_process() {
        let mut proof = ProcessProof::capture(std::process::id()).unwrap();
        proof.validate().unwrap();
        proof.started_at.push_str("-stale");
        assert!(proof.validate().is_err());
        proof.pid = u32::MAX;
        assert!(proof.validate().is_err());
    }

    #[test]
    fn fixed_handoff_rejects_unproved_identity() {
        let (manifest, _) = fixture();
        assert!(validate_terminal_ids(&manifest).is_err());
    }
}
