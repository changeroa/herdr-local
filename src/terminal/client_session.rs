//! Pure ownership and sequence arbitration for foreground-verified clients.
//! OS proof validation belongs to the runtime before these mutations execute.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexClientProof {
    pub(crate) process_id: u32,
    pub(crate) started_at: String,
    pub(crate) terminal_id: String,
    pub(crate) seq: u64,
}

pub(super) struct CodexClientOwner {
    proof: CodexClientProof,
    pub(super) verified_at: Instant,
}

impl TerminalState {
    pub(crate) fn codex_client_proof(&self) -> Option<&CodexClientProof> {
        self.codex_client_owner.as_ref().map(|owner| &owner.proof)
    }

    pub(crate) fn accepts_codex_client_proof(&self, proof: &CodexClientProof) -> bool {
        proof.process_id != 0
            && !proof.started_at.is_empty()
            && proof.terminal_id == self.id.as_str()
            && self
                .codex_client_sequences
                .get(&(proof.process_id, proof.started_at.clone()))
                .is_none_or(|seq| proof.seq > *seq)
    }

    pub(crate) fn set_verified_codex_client_session(
        &mut self,
        proof: CodexClientProof,
        session_ref: Option<crate::agent_resume::AgentSessionRef>,
    ) -> Option<TerminalStateMutation> {
        if !self.accepts_codex_client_proof(&proof) {
            return None;
        }
        let now = Instant::now();
        let previous_agent_label = self.effective_agent_label().map(str::to_string);
        let previous_known_agent = self.effective_known_agent();
        let previous_state = self.state;
        let previous_presentation = self.effective_presentation_for_state_at(previous_state, now);
        let previous_session = self.current_session_identity_for_persistence();

        self.codex_client_sequences
            .insert((proof.process_id, proof.started_at.clone()), proof.seq);
        self.codex_client_owner = Some(CodexClientOwner {
            proof,
            verified_at: now,
        });
        // A verified foreground client supersedes stale hook/session identity.
        // It does not provide working/idle authority; PTY detection owns that.
        if self
            .hook_authority
            .as_ref()
            .is_some_and(|authority| authority.agent_label != "codex")
        {
            self.hook_authority = None;
        } else if let Some(authority) = self.hook_authority.as_mut() {
            // Preserve same-agent lifecycle state from custom integrations,
            // while the verified client exclusively owns the session reference.
            authority.session_ref = None;
        }
        self.recent_agent_process_exit = None;
        if self.detected_agent != Some(Agent::Codex) {
            self.detected_agent = Some(Agent::Codex);
            self.fallback_state = AgentState::Unknown;
            self.fallback_visible_blocker = false;
        }
        self.reconcile_agent_name_owner("codex", session_ref.as_ref());
        self.persisted_agent_session =
            session_ref.map(|session_ref| crate::agent_resume::PersistedAgentSession {
                source: "herdr:codex-client".into(),
                agent: "codex".into(),
                session_ref,
            });
        Some(TerminalStateMutation {
            effective_state_change: self.recompute_effective_state(
                previous_agent_label,
                previous_known_agent,
                previous_state,
                previous_presentation,
                now,
            ),
            session_ref_changed: previous_session
                != self.current_session_identity_for_persistence(),
            agent_released: false,
        })
    }

    pub(crate) fn expire_codex_client_owner(
        &mut self,
        proof: &CodexClientProof,
    ) -> Option<TerminalStateMutation> {
        if self.codex_client_proof() != Some(proof) {
            return None;
        }
        self.codex_client_owner = None;
        // Keep the durable resume target. Live API projections hide client
        // sessions without an owner; a later heartbeat can revalidate it.
        let session_ref_changed = self
            .persisted_agent_session
            .as_ref()
            .is_some_and(|session| {
                session.source == "herdr:codex-client" && session.agent == "codex"
            });
        Some(TerminalStateMutation {
            session_ref_changed,
            ..TerminalStateMutation::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_resume::{AgentSessionRef, PersistedAgentSession};

    fn terminal() -> TerminalState {
        TerminalState::new(TerminalId::alloc(), PathBuf::from("/tmp"))
    }

    fn proof(terminal: &TerminalState, seq: u64) -> CodexClientProof {
        CodexClientProof {
            process_id: 42,
            started_at: "generation-1".into(),
            terminal_id: terminal.id.to_string(),
            seq,
        }
    }

    fn session(terminal: &TerminalState) -> Option<&str> {
        terminal
            .persisted_agent_session
            .as_ref()
            .map(|session| session.session_ref.value.as_str())
    }

    #[test]
    fn codex_client_select_replaces_legacy_and_fork_resume_sessions() {
        let mut terminal = terminal();
        terminal.set_persisted_agent_session(PersistedAgentSession {
            source: "herdr:codex".into(),
            agent: "codex".into(),
            session_ref: AgentSessionRef::id("contaminated").unwrap(),
        });
        for (seq, id) in [(1, "selected"), (2, "forked"), (3, "resumed")] {
            let mutation = terminal
                .set_verified_codex_client_session(proof(&terminal, seq), AgentSessionRef::id(id))
                .unwrap();
            assert!(mutation.session_ref_changed);
            assert_eq!(session(&terminal), Some(id));
            let saved = terminal.persisted_agent_session.as_ref().unwrap();
            assert_eq!(saved.source, "herdr:codex-client");
            assert_eq!(
                crate::agent_resume::plan(&saved.source, &saved.agent, &saved.session_ref)
                    .unwrap()
                    .argv,
                vec!["codex", "resume", id]
            );
        }
    }

    #[test]
    fn codex_client_session_keeps_custom_state_authority() {
        let mut terminal = terminal();
        terminal
            .set_hook_authority(
                "user:codex-status".into(),
                "codex".into(),
                AgentState::Working,
                None,
                Some(1),
            )
            .unwrap();
        for (seq, session_ref) in [(1, AgentSessionRef::id("selected")), (2, None)] {
            let mutation = terminal
                .set_verified_codex_client_session(proof(&terminal, seq), session_ref)
                .unwrap();
            assert!(mutation.effective_state_change.is_none());
            assert_eq!(terminal.state, AgentState::Working);
            assert_eq!(
                terminal.hook_authority.as_ref().unwrap().source,
                "user:codex-status"
            );
        }
    }

    #[test]
    fn codex_client_clear_retains_guard_against_legacy_and_unproved_sources() {
        let mut terminal = terminal();
        terminal
            .set_verified_codex_client_session(proof(&terminal, 1), AgentSessionRef::id("selected"))
            .unwrap();
        for seq in [2, 3] {
            if seq == 3 {
                terminal
                    .set_verified_codex_client_session(proof(&terminal, seq), None)
                    .unwrap();
                assert_eq!(session(&terminal), None);
            }
            for source in ["herdr:codex", "herdr:codex-client"] {
                assert!(terminal
                    .set_agent_session_ref_for_session_start(
                        source.into(),
                        "codex".into(),
                        AgentSessionRef::id("wrong"),
                        Some(1000),
                        Some("startup".into()),
                    )
                    .is_none());
                assert!(terminal
                    .set_hook_authority_with_session_ref(
                        source.into(),
                        "codex".into(),
                        AgentState::Working,
                        None,
                        AgentSessionRef::id("wrong"),
                        Some(1001),
                    )
                    .is_none());
                assert!(terminal
                    .release_agent_with_mutation(source, "codex", Some(1002))
                    .is_none());
            }
            assert!(terminal.codex_client_proof().is_some());
        }
        terminal
            .set_verified_codex_client_session(
                proof(&terminal, 4),
                AgentSessionRef::id("reselected"),
            )
            .unwrap();
        assert_eq!(session(&terminal), Some("reselected"));
    }

    #[test]
    fn codex_client_rejects_stale_sequence_and_wrong_terminal_without_mutation() {
        let mut terminal = terminal();
        terminal
            .set_verified_codex_client_session(proof(&terminal, 7), AgentSessionRef::id("current"))
            .unwrap();
        for seq in [0, 6, 7] {
            assert!(terminal
                .set_verified_codex_client_session(
                    proof(&terminal, seq),
                    AgentSessionRef::id("stale")
                )
                .is_none());
        }
        let mut wrong = proof(&terminal, 8);
        wrong.terminal_id = TerminalId::alloc().to_string();
        assert!(terminal
            .set_verified_codex_client_session(wrong, None)
            .is_none());
        assert_eq!(session(&terminal), Some("current"));
    }

    #[test]
    fn codex_client_new_generation_has_its_own_sequence_and_old_watermark_survives() {
        let mut terminal = terminal();
        let old = proof(&terminal, 50);
        terminal
            .set_verified_codex_client_session(old.clone(), AgentSessionRef::id("old"))
            .unwrap();
        let mut new = proof(&terminal, 1);
        new.started_at = "generation-2".into();
        terminal
            .set_verified_codex_client_session(new.clone(), AgentSessionRef::id("new"))
            .unwrap();
        assert!(terminal
            .set_verified_codex_client_session(old.clone(), None)
            .is_none());
        assert!(terminal.expire_codex_client_owner(&old).is_none());
        assert_eq!(terminal.codex_client_proof(), Some(&new));
        assert_eq!(session(&terminal), Some("new"));
    }

    #[test]
    fn codex_client_expiration_preserves_resume_target_and_allows_legacy_again() {
        let mut terminal = terminal();
        let proof = proof(&terminal, 1);
        terminal
            .set_verified_codex_client_session(proof.clone(), AgentSessionRef::id("selected"))
            .unwrap();
        terminal.expire_codex_client_owner(&proof).unwrap();
        assert!(terminal.codex_client_proof().is_none());
        assert_eq!(session(&terminal), Some("selected"));
        assert!(
            terminal
                .set_agent_session_ref_for_session_start(
                    "herdr:codex".into(),
                    "codex".into(),
                    AgentSessionRef::id("foreground-legacy"),
                    Some(1),
                    None,
                )
                .unwrap()
                .session_ref_changed
        );
        assert_eq!(session(&terminal), Some("foreground-legacy"));
    }

    #[test]
    fn codex_client_foreground_exit_clears_owner_but_old_observation_cannot() {
        let mut terminal = terminal();
        let old_observation = Instant::now() - Duration::from_secs(1);
        terminal
            .set_verified_codex_client_session(proof(&terminal, 1), AgentSessionRef::id("current"))
            .unwrap();
        terminal.set_detected_state_with_screen_signals_at(
            Some(Agent::Codex),
            AgentState::Unknown,
            false,
            false,
            false,
            true,
            old_observation,
        );
        assert!(terminal.codex_client_proof().is_some());
        assert_eq!(session(&terminal), Some("current"));
        terminal.set_detected_state_with_screen_signals_at(
            Some(Agent::Codex),
            AgentState::Unknown,
            false,
            false,
            false,
            true,
            Instant::now(),
        );
        assert!(terminal.codex_client_proof().is_none());
        assert_eq!(session(&terminal), None);
    }
}
