use super::*;

const DAEMON_LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;
const DAEMON_LOG_RETAIN_BYTES: u64 = DAEMON_LOG_MAX_BYTES;
const DAEMON_LOG_COMPACT_CHECK_SECS: u64 = 60;

include!("daemon_runtime/control_files.rs");
include!("daemon_runtime/network_cleanup_journal.rs");
include!("daemon_runtime/macos_cleanup.rs");
include!("daemon_runtime/runtime_files.rs");
include!("daemon_runtime/process_scan.rs");
include!("daemon_runtime/permissions_and_ping.rs");

include!("daemon_runtime/probe_route.rs");
