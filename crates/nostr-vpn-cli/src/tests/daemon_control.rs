use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nostr_sdk::prelude::Keys;

use crate::*;

include!("daemon_control/state_and_logs.rs");
include!("daemon_control/fips_and_routes.rs");
include!("daemon_control/endpoint_live_status.rs");
include!("daemon_control/pid_and_service.rs");
include!("daemon_control/config_and_control.rs");
