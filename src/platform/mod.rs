//! Platform-specific process and filesystem operations.
//!
//! Centralizes OS-dependent behavior behind a clean boundary so core
//! modules don't scatter `#[cfg]` branches through product logic.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundProcess {
    pub pid: u32,
    pub name: String,
    pub argv0: Option<String>,
    pub argv: Option<Vec<String>>,
    pub cmdline: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundJob {
    pub process_group_id: u32,
    pub processes: Vec<ForegroundProcess>,
}

/// Check the exact process, rather than another Codex in the same job. Read the
/// generation on both sides of enumeration so PID reuse fails closed.
pub(crate) fn verify_codex_client_process(
    child_pid: u32,
    process_id: u32,
    started_at: &str,
) -> bool {
    verify_codex_client_process_with(
        child_pid,
        process_id,
        started_at,
        process_started_at,
        foreground_job_for_client_registration,
    )
}

fn verify_codex_client_process_with(
    child_pid: u32,
    process_id: u32,
    started_at: &str,
    mut process_generation: impl FnMut(u32) -> Option<String>,
    foreground: impl FnOnce(u32) -> Option<ForegroundJob>,
) -> bool {
    if process_id == 0
        || started_at.is_empty()
        || process_generation(process_id).as_deref() != Some(started_at)
    {
        return false;
    }
    let Some(job) = foreground(child_pid) else {
        return false;
    };
    let Some(process) = job
        .processes
        .into_iter()
        .find(|process| process.pid == process_id)
    else {
        return false;
    };
    let exact_job = ForegroundJob {
        process_group_id: process_id,
        processes: vec![process],
    };
    crate::detect::identify_agent_in_job(&exact_job)
        .is_some_and(|(agent, _)| agent == crate::detect::Agent::Codex)
        && process_generation(process_id).as_deref() == Some(started_at)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Hangup,
    Terminate,
    Kill,
}

pub(crate) fn detached_custom_command_process(command: &str) -> std::process::Command {
    let mut process = detached_custom_command_process_platform(command);
    configure_background_command(&mut process);
    process
}

pub(crate) fn pane_custom_command_pty_builder(command: &str) -> portable_pty::CommandBuilder {
    pane_custom_command_pty_builder_platform(command)
}

pub(crate) fn apply_pane_runtime_marker(command: &mut portable_pty::CommandBuilder) {
    apply_pane_runtime_marker_platform(command);
}

#[cfg(not(windows))]
pub(crate) fn terminal_title_for_presentation(title: &str) -> &str {
    title
}

#[cfg(not(windows))]
fn apply_pane_runtime_marker_platform(_command: &mut portable_pty::CommandBuilder) {}

pub(crate) fn configure_background_command(command: &mut std::process::Command) {
    configure_background_command_platform(command);
}

#[cfg(not(windows))]
fn configure_background_command_platform(_command: &mut std::process::Command) {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlatformCapabilities {
    pub(crate) live_handoff: bool,
    pub(crate) direct_terminal_attach: bool,
    pub(crate) preserve_legacy_doubled_escape_input: bool,
}

pub(crate) const fn capabilities() -> PlatformCapabilities {
    PlatformCapabilities {
        live_handoff: cfg!(unix),
        direct_terminal_attach: cfg!(unix),
        preserve_legacy_doubled_escape_input: cfg!(target_os = "macos"),
    }
}

#[cfg(not(windows))]
pub fn launch_server_daemon_command(command: &mut std::process::Command) -> std::io::Result<u32> {
    command.spawn().map(|child| child.id())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn detach_server_daemon_command(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn current_process_is_detached_server_daemon() -> bool {
    unsafe { libc::getsid(0) == libc::getpid() }
}

/// Raised by the SIGWINCH handler, consumed by the host resize watcher.
#[cfg(unix)]
static TERMINAL_RESIZE_SIGNALLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn record_terminal_resize_signal(_signal: libc::c_int) {
    TERMINAL_RESIZE_SIGNALLED.store(true, std::sync::atomic::Ordering::Release);
}

/// Records SIGWINCH events that size polling can miss.
#[cfg(unix)]
pub(crate) fn watch_terminal_resize_signal() {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction =
        record_terminal_resize_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // Keep blocking stdin and socket reads from failing with EINTR.
    action.sa_flags = libc::SA_RESTART;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGWINCH, &action, std::ptr::null_mut());
    }
}

#[cfg(not(unix))]
pub(crate) fn watch_terminal_resize_signal() {}

/// Returns whether a terminal size change was signalled since the last call.
#[cfg(unix)]
pub(crate) fn take_terminal_resize_signal() -> bool {
    TERMINAL_RESIZE_SIGNALLED.swap(false, std::sync::atomic::Ordering::AcqRel)
}

/// Windows relies on size polling.
#[cfg(not(unix))]
pub(crate) fn take_terminal_resize_signal() -> bool {
    false
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardCommand {
    pub program: &'static str,
    pub args: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardImage {
    pub bytes: Vec<u8>,
    pub extension: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LimitedRead {
    Empty,
    Complete(Vec<u8>),
    Oversized,
}

pub(crate) fn read_limited_reader(
    mut reader: impl std::io::Read,
    max_bytes: usize,
) -> std::io::Result<LimitedRead> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];

    while bytes.len() < max_bytes {
        let remaining = max_bytes - bytes.len();
        let read_len = remaining.min(buffer.len());
        let bytes_read = match reader.read(&mut buffer[..read_len]) {
            Ok(bytes_read) => bytes_read,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        if bytes_read == 0 {
            return if bytes.is_empty() {
                Ok(LimitedRead::Empty)
            } else {
                Ok(LimitedRead::Complete(bytes))
            };
        }
        bytes.extend_from_slice(&buffer[..bytes_read]);
    }

    let mut sentinel = [0_u8; 1];
    loop {
        return match reader.read(&mut sentinel) {
            Ok(0) if bytes.is_empty() => Ok(LimitedRead::Empty),
            Ok(0) => Ok(LimitedRead::Complete(bytes)),
            Ok(_) => Ok(LimitedRead::Oversized),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => Err(err),
        };
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RemoteSshConfigPaths {
    pub(crate) user_config: Option<std::path::PathBuf>,
    pub(crate) system_config: Option<std::path::PathBuf>,
    pub(crate) multiplexing: bool,
}

#[cfg(unix)]
mod unix_common;
#[cfg(unix)]
pub(crate) use unix_common::{begin_cli_output, end_cli_output};

#[cfg(not(unix))]
pub(crate) fn begin_cli_output() {}

#[cfg(not(unix))]
pub(crate) fn end_cli_output() {}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod fallback;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub use fallback::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn available_pane_shell_from_job(child_pid: u32, job: ForegroundJob) -> Option<String> {
    if job.process_group_id != child_pid
        || job.processes.iter().any(|process| process.pid != child_pid)
    {
        return None;
    }
    job.processes
        .into_iter()
        .find(|process| process.pid == child_pid)
        .map(|process| process.name)
        .filter(|name| is_pane_shell_process_name(name))
}

fn normalized_process_name(name: &str) -> String {
    name.rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim_start_matches('-')
        .trim_end_matches(".exe")
        .to_ascii_lowercase()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn is_powershell_process_name(name: &str) -> bool {
    matches!(
        normalized_process_name(name).as_str(),
        "pwsh" | "powershell"
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn interactive_unix_shell_command(
    argv: &[String],
    shell_name: &str,
    quote_posix_arg: fn(&str) -> String,
) -> Option<String> {
    let quote = if is_powershell_process_name(shell_name) {
        quote_powershell_arg
    } else {
        quote_posix_arg
    };
    let mut parts = argv.iter();
    let mut command = quote(parts.next()?);
    for part in parts {
        command.push(' ');
        command.push_str(&quote(part));
    }
    Some(command)
}

pub(crate) fn quote_powershell_arg(value: &str) -> String {
    if !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':' | b'+' | b'=')
        })
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "''"))
}

pub(crate) fn is_pane_shell_process_name(name: &str) -> bool {
    let normalized = normalized_process_name(name);
    matches!(
        normalized.as_str(),
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "fish"
            | "ksh"
            | "mksh"
            | "csh"
            | "tcsh"
            | "elvish"
            | "xonsh"
            | "nu"
            | "pwsh"
            | "powershell"
            | "cmd"
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn process_agent_hint(_pid: u32) -> Option<crate::detect::Agent> {
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn parse_agent_env_hint(environ: &[u8]) -> Option<crate::detect::Agent> {
    for record in environ.split(|&byte| byte == 0) {
        let Some(value) = record.strip_prefix(b"HERDR_AGENT=") else {
            continue;
        };
        return crate::detect::parse_agent_label(std::str::from_utf8(value).ok()?);
    }
    None
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[derive(Debug)]
pub(crate) struct InputSourceRestore;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(crate) fn switch_to_ascii_input_source() -> Option<InputSourceRestore> {
    None
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(crate) fn pump_input_source_runloop() {}

/// Switches the host keyboard input source while prefix mode is active.
///
/// `App` drives this through a trait so the prefix-mode transitions can be
/// tested with a fake, without touching the real macOS APIs or leaking a
/// platform-specific restore type into `App`.
pub(crate) trait PrefixInputSource {
    /// Switch to an ASCII-capable input source for prefix commands. No-op if
    /// the current source is already ASCII-capable, the platform is
    /// unsupported, or the switch fails. Calling it again before `restore`
    /// keeps the source saved by the first call.
    fn switch_to_ascii(&mut self);

    /// Restore whatever `switch_to_ascii` saved. No-op if nothing was switched.
    fn restore(&mut self);
}

/// Production [`PrefixInputSource`] backed by the per-platform API.
#[derive(Default)]
pub(crate) struct RealPrefixInputSource {
    restore: Option<InputSourceRestore>,
}

impl PrefixInputSource for RealPrefixInputSource {
    fn switch_to_ascii(&mut self) {
        if self.restore.is_none() {
            // Drain pending input-source-change notifications so the read below is fresh (see
            // `pump_input_source_runloop`); a no-op on non-macOS.
            pump_input_source_runloop();
            self.restore = switch_to_ascii_input_source();
        }
    }

    fn restore(&mut self) {
        let _ = self.restore.take();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn codex_client_job(pid: u32, name: &str) -> ForegroundJob {
        ForegroundJob {
            process_group_id: pid,
            processes: vec![ForegroundProcess {
                pid,
                name: name.into(),
                argv0: None,
                argv: None,
                cmdline: None,
            }],
        }
    }

    #[test]
    fn codex_client_foreground_proof_requires_exact_pid_agent_and_generation() {
        assert!(verify_codex_client_process_with(
            10,
            42,
            "start",
            |_| Some("start".into()),
            |_| Some(codex_client_job(42, "codex"))
        ));
        for (pid, name, generation) in [
            (43, "codex", "start"),
            (42, "sleep", "start"),
            (42, "codex", "reused"),
        ] {
            assert!(!verify_codex_client_process_with(
                10,
                42,
                "start",
                |_| Some(generation.into()),
                |_| Some(codex_client_job(pid, name))
            ));
        }
        // A still-live Codex that has been backgrounded is no longer the owner.
        assert!(!verify_codex_client_process_with(
            10,
            42,
            "start",
            |_| Some("start".into()),
            |_| Some(codex_client_job(99, "codex"))
        ));
        assert!(!verify_codex_client_process_with(
            10,
            42,
            "start",
            |_| Some("start".into()),
            |_| None
        ));
        assert!(!verify_codex_client_process_with(
            10,
            42,
            "start",
            |_| None,
            |_| Some(codex_client_job(42, "codex"))
        ));
    }

    #[test]
    fn codex_client_foreground_proof_rechecks_generation_after_enumeration() {
        let mut generations = [Some("before".into()), Some("after".into())].into_iter();
        assert!(!verify_codex_client_process_with(
            10,
            42,
            "before",
            |_| generations.next().flatten(),
            |_| Some(codex_client_job(42, "codex"))
        ));
        // A Codex elsewhere in the same foreground group cannot validate a shell PID.
        let mut job = codex_client_job(42, "bash");
        job.processes
            .extend(codex_client_job(43, "codex").processes);
        assert!(!verify_codex_client_process_with(
            10,
            42,
            "start",
            |_| Some("start".into()),
            |_| Some(job)
        ));
    }

    #[test]
    fn codex_client_current_process_generation_is_stable_when_supported() {
        let first = process_started_at(std::process::id());
        if cfg!(any(target_os = "macos", target_os = "linux", windows)) {
            assert!(first.as_ref().is_some_and(|stamp| !stamp.is_empty()));
        }
        assert_eq!(first, process_started_at(std::process::id()));
        assert_eq!(process_started_at(u32::MAX), None);
    }

    #[test]
    fn terminal_resize_signal_is_recorded_once_per_delivery() {
        watch_terminal_resize_signal();
        assert!(!take_terminal_resize_signal());

        unsafe {
            libc::raise(libc::SIGWINCH);
        }

        assert!(take_terminal_resize_signal());
        assert!(!take_terminal_resize_signal());
    }

    #[test]
    fn pane_shell_process_names_reject_exec_replacement_programs() {
        for shell in ["bash", "-zsh", "/bin/fish", "pwsh", "powershell.exe"] {
            assert!(is_pane_shell_process_name(shell), "{shell}");
        }
        for program in ["vim", "nvim", "cargo", "test-runner", "opencode"] {
            assert!(!is_pane_shell_process_name(program), "{program}");
        }
    }

    #[test]
    fn detached_custom_command_preserves_unix_login_shell_flag() {
        let cmd = detached_custom_command_process("echo hello");
        assert_eq!(cmd.get_program(), std::ffi::OsStr::new("/bin/sh"));
        assert_eq!(
            cmd.get_args().collect::<Vec<_>>(),
            [
                std::ffi::OsStr::new("-lc"),
                std::ffi::OsStr::new("echo hello")
            ]
        );
    }

    #[test]
    fn pane_custom_command_builder_preserves_unix_shell_flag() {
        let expected: Vec<std::ffi::OsString> =
            vec!["/bin/sh".into(), "-c".into(), "echo hello".into()];
        assert_eq!(
            pane_custom_command_pty_builder("echo hello").get_argv(),
            &expected
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn parse_agent_env_hint_accepts_known_agents() {
        assert_eq!(
            parse_agent_env_hint(b"PATH=/bin\0HERDR_AGENT=claude\0TERM=xterm\0"),
            Some(crate::detect::Agent::Claude)
        );
        assert_eq!(
            parse_agent_env_hint(b"HERDR_AGENT=codex"),
            Some(crate::detect::Agent::Codex)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn parse_agent_env_hint_ignores_missing_or_unknown_agents() {
        assert_eq!(parse_agent_env_hint(b"PATH=/bin\0TERM=xterm\0"), None);
        assert_eq!(parse_agent_env_hint(b"HERDR_AGENT=not-an-agent\0"), None);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn interactive_shell_command_quotes_for_posix_and_powershell() {
        let argv = vec![
            "pi".into(),
            String::new(),
            "two words".into(),
            "a'b".into(),
            "$HOME".into(),
            "semi;colon".into(),
            "@options".into(),
        ];
        assert_eq!(
            interactive_shell_command(&argv, "bash").as_deref(),
            Some("pi '' 'two words' 'a'\\''b' '$HOME' 'semi;colon' @options")
        );
        assert_eq!(
            interactive_shell_command(&argv, "pwsh").as_deref(),
            Some("pi '' 'two words' 'a''b' '$HOME' 'semi;colon' '@options'")
        );
    }

    #[test]
    fn read_limited_reader_returns_complete_data_under_limit() {
        let input = std::io::Cursor::new(b"image".to_vec());
        assert_eq!(
            read_limited_reader(input, 16).expect("limited read"),
            LimitedRead::Complete(b"image".to_vec())
        );
    }

    #[test]
    fn read_limited_reader_returns_empty_for_empty_input() {
        let input = std::io::Cursor::new(Vec::<u8>::new());
        assert_eq!(
            read_limited_reader(input, 16).expect("limited read"),
            LimitedRead::Empty
        );
    }

    #[test]
    fn read_limited_reader_accepts_data_exactly_at_limit() {
        let input = std::io::Cursor::new(b"four".to_vec());
        assert_eq!(
            read_limited_reader(input, 4).expect("limited read"),
            LimitedRead::Complete(b"four".to_vec())
        );
    }

    #[test]
    fn read_limited_reader_rejects_data_over_limit() {
        let input = std::io::Cursor::new(b"oversized".to_vec());
        assert_eq!(
            read_limited_reader(input, 4).expect("limited read"),
            LimitedRead::Oversized
        );
    }

    #[test]
    fn read_limited_reader_retries_interrupted_reads() {
        struct InterruptedOnce {
            interrupted: bool,
            inner: std::io::Cursor<Vec<u8>>,
        }

        impl std::io::Read for InterruptedOnce {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                self.inner.read(buffer)
            }
        }

        let input = InterruptedOnce {
            interrupted: false,
            inner: std::io::Cursor::new(b"image".to_vec()),
        };
        assert_eq!(
            read_limited_reader(input, 16).expect("limited read"),
            LimitedRead::Complete(b"image".to_vec())
        );
    }
}
