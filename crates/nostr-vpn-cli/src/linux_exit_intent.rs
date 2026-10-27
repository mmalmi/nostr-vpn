//! Durable desired policy is separate from disposable tunnel cleanup state.
//! Restart, failed setup, and tunnel loss never imply an explicit Direct choice.

use crate::linux_exit_guard::{ForwardedExit, GuardRoute, KernelPolicy, LinuxExitGuard};
use anyhow::{Context, Result, anyhow};
use nostr_vpn_core::config::{AppConfig, InternetSource};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
static POLICY: OnceLock<Mutex<Policy>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedIntent {
    version: u8,
    owner: String,
    /// None means explicit Direct/pause; Some(false) allows native fallback.
    protection: Option<bool>,
}

struct Policy {
    path: PathBuf,
    saved: SavedIntent,
    routes: Vec<GuardRoute>,
    forwarded: Option<ForwardedExit>,
    applied: Option<LinuxExitGuard>,
    kernel_policy: Option<KernelPolicy>,
    last_checked: Option<Instant>,
}

fn desired(app: &AppConfig, enabled: bool) -> Option<bool> {
    // Match the established migration of configs written before internet_source.
    let exit = app.internet_source != InternetSource::Direct
        || app.wireguard_exit.enabled
        || !app.exit_node.trim().is_empty();
    (enabled && exit).then_some(app.exit_node_leak_protection)
}

impl Policy {
    fn open(config_path: &Path) -> Result<Self> {
        // This must be readable before login or mounting an encrypted home.
        // The service installer writes an absolute, canonical config argument.
        let absolute = if config_path.is_absolute() {
            config_path.to_path_buf()
        } else {
            std::env::current_dir()?.join(config_path)
        };
        let identity = absolute;
        let key = hex::encode(sha2::Sha256::digest(
            identity.as_os_str().as_encoded_bytes(),
        ));
        let path = Path::new("/var/lib/nvpn/egress").join(format!("{key}.json"));
        if let Some(parent) = path.parent().filter(|parent| parent.exists()) {
            crate::set_daemon_cleanup_directory_permissions(parent)?;
        }
        let saved = read_saved(&path)?.unwrap_or_else(|| SavedIntent {
            version: 1,
            owner: hex::encode(rand::random::<[u8; 16]>()),
            protection: None,
        });
        Ok(Self {
            path,
            saved,
            routes: Vec::new(),
            forwarded: None,
            applied: None,
            kernel_policy: None,
            last_checked: None,
        })
    }

    fn guard(&self) -> LinuxExitGuard {
        // Native routes admit their subnets by destination in the firewall;
        // their physical interfaces must never join the tunnel accept list.
        let mut interfaces = self
            .routes
            .iter()
            .filter(|route| !route.native)
            .map(|route| route.interface.clone())
            .collect::<Vec<_>>();
        interfaces.sort();
        interfaces.dedup();
        let mut vpn_sources = netdev::get_interfaces()
            .into_iter()
            .filter(|interface| interfaces.contains(&interface.name))
            .flat_map(|interface| interface.ipv4.into_iter().map(|network| network.addr()))
            .collect::<Vec<_>>();
        vpn_sources.sort_unstable();
        vpn_sources.dedup();
        LinuxExitGuard {
            owner: self.saved.owner.clone(),
            fail_closed: self.saved.protection.unwrap_or(false),
            vpn_sources,
            forwarded: self.forwarded.clone(),
            interfaces,
            routes: self.routes.clone(),
        }
    }

    fn reconcile(&mut self, force: bool) -> Result<()> {
        // A Direct-only process can still refresh or stop its mesh interface.
        // Those lifecycle calls must not invoke nft for policy it never owned.
        if self.saved.protection.is_none() && self.forwarded.is_none() && !self.path.exists() {
            self.applied = None;
            return Ok(());
        }
        let guard = self.guard();
        if !force && self.applied.as_ref() == Some(&guard) {
            if (self.saved.protection.is_none() && self.forwarded.is_none())
                || self
                    .last_checked
                    .is_some_and(|checked| checked.elapsed() < Duration::from_secs(5))
            {
                return Ok(());
            }
            self.last_checked = Some(Instant::now());
            if self.kernel_policy.as_ref() == Some(&guard.kernel_policy()?) {
                return Ok(());
            }
        }
        // An interrupted apply must be retried even when desired input matches.
        self.applied = None;
        if self.saved.protection.is_some() || self.forwarded.is_some() {
            guard
                .apply(self.kernel_policy.as_ref())
                .context("failed to apply Linux egress protection")?;
            self.kernel_policy = Some(guard.kernel_policy()?);
        } else {
            guard
                .release(self.kernel_policy.as_ref())
                .context("failed to release Linux egress protection")?;
            self.kernel_policy = None;
        }
        self.last_checked = Some(Instant::now());
        self.applied = Some(guard);
        Ok(())
    }

    fn set_desired(&mut self, protection: Option<bool>) -> Result<()> {
        // A new Direct-only configuration has never owned kernel policy. Do
        // not require firewall tooling or create a cleanup obligation for it.
        if protection.is_none() && self.forwarded.is_none() && !self.path.exists() {
            self.saved.protection = None;
            self.routes.clear();
            self.forwarded = None;
            self.applied = Some(self.guard());
            return Ok(());
        }
        let mut next = self.saved.clone();
        next.protection = protection;
        if next != self.saved || !self.path.exists() {
            let parent = self.path.parent().expect("intent has parent");
            std::fs::create_dir_all(parent)?;
            crate::set_daemon_cleanup_directory_permissions(parent)?;
            crate::write_private_runtime_file_durably(&self.path, &serde_json::to_vec(&next)?)?;
            self.saved = next;
            self.applied = None;
        }
        if protection.is_none() {
            self.routes.clear();
            // Pause/Direct releases local applications immediately, but the
            // old seller ingress must remain blocked until the runtime has
            // closed admissions and reconciled its forwarding configuration.
            // With no routes, local lookups fall through the throw default;
            // selected forwarded packets hit their terminal rejection rule.
        }
        self.reconcile(false)
    }
}

fn read_saved(path: &Path) -> Result<Option<SavedIntent>> {
    let file = match crate::runtime_open_options_no_follow()
        .read(true)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("failed to read Linux egress intent"),
    };
    let metadata = crate::validate_daemon_runtime_file(&file, path)?;
    if metadata.len() > 1024 {
        return Err(anyhow!("Linux egress intent exceeds its size limit"));
    }
    let saved: SavedIntent = serde_json::from_reader(file)
        .context("refusing to discard unreadable Linux egress intent")?;
    if saved.version != 1 {
        return Err(anyhow!("unsupported Linux egress intent version"));
    }
    Ok(Some(saved))
}

/// The daemon instance lock (or service installation ordering) serializes this
/// before legacy route/DNS cleanup. No keyring or network awaits are involved.
#[cfg(target_os = "linux")]
pub(crate) fn initialize(config_path: &Path, enabled_override: Option<bool>) -> Result<()> {
    if POLICY.get().is_some() {
        return Err(anyhow!("Linux egress intent initialized twice"));
    }
    let identity = std::fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf());
    let mut policy = Policy::open(&identity)?;
    // First recover the last durable protection. A broken or unavailable config
    // must not silently clear protection on boot or restart.
    if policy.saved.protection.is_some() {
        policy.reconcile(true)?;
    }
    let protection = read_desired(config_path, enabled_override, policy.saved.protection)?;
    policy.set_desired(protection)?;
    POLICY
        .set(Mutex::new(policy))
        .map_err(|_| anyhow!("Linux egress intent initialized twice"))
}

/// Boot uses only root-owned intent, before networking or user-home availability.
/// No stop hook: stopping/restarting this service must never clear protection.
#[cfg(target_os = "linux")]
pub(crate) fn restore_at_boot(config_path: &Path) -> Result<()> {
    let mut policy = Policy::open(config_path)?;
    if policy.path.exists() {
        policy.reconcile(true)?;
    }
    Ok(())
}

/// Explicit service removal restores normal access after its daemon is stopped.
#[cfg(target_os = "linux")]
pub(crate) fn release_for_uninstall(config_path: &Path) -> Result<()> {
    Policy::open(config_path)?.set_desired(None)
}

fn read_desired(
    config_path: &Path,
    enabled_override: Option<bool>,
    previous: Option<bool>,
) -> Result<Option<bool>> {
    let app: AppConfig = match std::fs::read_to_string(config_path) {
        Ok(raw) => toml::from_str(&raw).context("failed to read Linux egress settings")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && previous.is_none() => {
            AppConfig::default()
        }
        Err(error) => return Err(error).context("Linux egress settings are unavailable"),
    };
    Ok(desired(&app, enabled_override.unwrap_or(app.autoconnect)))
}

#[cfg(target_os = "linux")]
pub(crate) fn update(app: &AppConfig, enabled: bool) -> Result<()> {
    with_policy(|policy| policy.set_desired(desired(app, enabled)))
}

/// Read back installed policy periodically; repair only when kernel state
/// changed. The daemon and foreground connect share the same enforcement.
#[cfg(target_os = "linux")]
pub(crate) fn maintain() -> Result<()> {
    with_policy(|policy| policy.reconcile(false))
}

#[cfg(target_os = "linux")]
pub(crate) fn routes(mut routes: Vec<GuardRoute>, forwarded: Option<ForwardedExit>) -> Result<()> {
    routes.sort_by(|a, b| a.target.cmp(&b.target));
    with_policy(|policy| {
        policy.routes = routes;
        policy.forwarded = forwarded;
        policy.set_desired(policy.saved.protection)
    })
}

/// Remove permissions before tearing down an interface, retaining desired
/// protection. A new interface with the same name must not inherit admission.
#[cfg(target_os = "linux")]
pub(crate) fn pending() -> Result<()> {
    with_policy(|policy| {
        policy.routes.clear();
        policy.reconcile(true)
    })
}

#[cfg(target_os = "linux")]
fn with_policy(action: impl FnOnce(&mut Policy) -> Result<()>) -> Result<()> {
    let policy = POLICY
        .get()
        .ok_or_else(|| anyhow!("Linux egress intent is not initialized"))?;
    let mut policy = policy
        .lock()
        .map_err(|_| anyhow!("Linux egress intent lock poisoned"))?;
    action(&mut policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "run with scripts/test-linux-egress-lifecycle in an isolated root namespace"]
    fn pause_blocks_forwarding_until_runtime_withdraws_it() {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        assert_eq!(std::env::var("NVPN_EGRESS_ISOLATED").as_deref(), Ok("1"));
        assert!(Path::new("/var/lib/nvpn-egress-fixture").exists());
        assert_eq!(std::fs::read_dir("/sys/class/net").unwrap().count(), 1);
        let run = |args: &[&str]| {
            let output = Command::new("ip").args(args).output().unwrap();
            assert!(
                output.status.success(),
                "ip {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run(&["link", "set", "lo", "up"]);
        for (namespace, interface, host, peer) in [
            ("physical-peer", "physical", "192.0.2.1/24", "192.0.2.2/24"),
            ("buyer", "mesh", "10.44.0.1/16", "10.44.0.2/16"),
        ] {
            run(&["netns", "add", namespace]);
            run(&[
                "link", "add", interface, "type", "veth", "peer", "name", "remote",
            ]);
            run(&["link", "set", "remote", "netns", namespace]);
            run(&["addr", "add", host, "dev", interface]);
            run(&["link", "set", interface, "up"]);
            run(&["netns", "exec", namespace, "ip", "link", "set", "lo", "up"]);
            run(&[
                "netns", "exec", namespace, "ip", "addr", "add", peer, "dev", "remote",
            ]);
            run(&[
                "netns", "exec", namespace, "ip", "link", "set", "remote", "up",
            ]);
        }
        run(&["route", "add", "default", "via", "192.0.2.2"]);
        run(&[
            "netns",
            "exec",
            "physical-peer",
            "ip",
            "route",
            "add",
            "10.44.0.0/16",
            "via",
            "192.0.2.1",
        ]);
        run(&[
            "netns",
            "exec",
            "buyer",
            "ip",
            "route",
            "add",
            "default",
            "via",
            "10.44.0.1",
        ]);
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
        let received = "/tmp/forwarding-received";
        let mut receiver = Command::new("ip").args(["netns", "exec", "physical-peer", "python3", "-u", "-c",
            "import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.bind(('192.0.2.2',39001))\nprint('ready',flush=True)\nwhile True:\n data,_=s.recvfrom(64)\n with open('/tmp/forwarding-received','ab') as f: f.write(data+b'\\n')"])
            .stdout(Stdio::piped()).spawn().unwrap();
        let mut ready = String::new();
        std::io::BufReader::new(receiver.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready.trim(), "ready");
        let send = |label: &str| {
            run(&[
                "netns",
                "exec",
                "buyer",
                "python3",
                "-c",
                "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(sys.argv[1].encode(),('192.0.2.2',39001))",
                label,
            ]);
            std::thread::sleep(Duration::from_millis(150));
        };
        send("before");
        assert_eq!(std::fs::read_to_string(received).unwrap(), "before\n");
        let mut policy = Policy::open(Path::new("/tmp/forwarding-config.toml")).unwrap();
        policy.set_desired(Some(true)).unwrap();
        policy.routes = vec![GuardRoute {
            target: "0.0.0.0/0".into(),
            interface: "mesh".into(),
            gateway: None,
            native: false,
        }];
        policy.forwarded = Some(ForwardedExit {
            interface: "mesh".into(),
            source: "10.44.0.0/16".into(),
        });
        policy.reconcile(true).unwrap();
        send("active");
        policy.set_desired(None).unwrap();
        // Keep sending as an already admitted buyer after the local pause.
        // Runtime admission withdrawal has deliberately not happened yet.
        send("paused");
        assert_eq!(std::fs::read_to_string(received).unwrap(), "before\n");
        let local = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        local.send_to(b"local-direct", "192.0.2.2:39001").unwrap();
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(
            std::fs::read_to_string(received).unwrap(),
            "before\nlocal-direct\n"
        );
        // The runtime can now retire the old ingress after closing admission,
        // or select Direct deliberately. Ordinary forwarding is then restored.
        policy.forwarded = None;
        policy.set_desired(None).unwrap();
        send("released");
        assert_eq!(
            std::fs::read_to_string(received).unwrap(),
            "before\nlocal-direct\nreleased\n"
        );
        receiver.kill().unwrap();
        receiver.wait().unwrap();
    }

    #[test]
    fn durable_intent_readback_preserves_protection_and_rejects_linked_or_corrupt_files() {
        let directory =
            std::env::temp_dir().join(format!("nvpn-egress-intent-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("egress.intent.json");
        let saved = SavedIntent {
            version: 1,
            owner: "fixture-owner".into(),
            protection: Some(true),
        };
        crate::write_private_runtime_file_durably(&path, &serde_json::to_vec(&saved).unwrap())
            .unwrap();
        assert_eq!(read_saved(&path).unwrap(), Some(saved));
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let link = directory.join("symlink");
            symlink(&path, &link).unwrap();
            assert!(read_saved(&link).is_err());
            let hardlink = directory.join("hardlink");
            std::fs::hard_link(&path, &hardlink).unwrap();
            assert!(read_saved(&path).is_err());
            std::fs::remove_file(hardlink).unwrap();
        }
        std::fs::write(&path, b"{").unwrap();
        assert!(read_saved(&path).is_err());
        assert!(path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn never_owned_direct_policy_skips_kernel_work_on_refresh_and_stop() {
        let path = std::env::temp_dir().join(format!("nvpn-no-intent-{}", rand::random::<u64>()));
        let mut policy = Policy {
            path: path.clone(),
            // A kernel operation would reject this owner before invoking any
            // system command, making this test safe even on a privileged host.
            saved: SavedIntent {
                version: 1,
                owner: "invalid/unused".into(),
                protection: None,
            },
            routes: Vec::new(),
            forwarded: None,
            applied: None,
            kernel_policy: None,
            last_checked: None,
        };
        policy.set_desired(None).unwrap();
        policy.routes.push(GuardRoute {
            target: "10.44.0.0/16".into(),
            interface: "nvpn0".into(),
            gateway: None,
            native: false,
        });
        policy.reconcile(false).unwrap();
        policy.routes.clear();
        policy.reconcile(true).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn boot_reads_serialized_auto_selection_before_a_provider_exists_and_honors_pause() {
        let directory =
            std::env::temp_dir().join(format!("nvpn-egress-intent-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("config.toml");
        let mut app = AppConfig {
            internet_source: InternetSource::PaidAutomatic,
            exit_node_leak_protection: true,
            exit_node: String::new(),
            ..AppConfig::default()
        };
        std::fs::write(&path, app.plaintext_toml().unwrap()).unwrap();
        assert_eq!(read_desired(&path, None, None).unwrap(), Some(true));
        app.autoconnect = false;
        std::fs::write(&path, app.plaintext_toml().unwrap()).unwrap();
        assert_eq!(read_desired(&path, None, Some(true)).unwrap(), None);
        assert_eq!(read_desired(&path, Some(true), None).unwrap(), Some(true));
        app.autoconnect = true;
        app.exit_node_leak_protection = false;
        std::fs::write(&path, app.plaintext_toml().unwrap()).unwrap();
        assert_eq!(read_desired(&path, None, Some(true)).unwrap(), Some(false));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn boot_migrates_legacy_exit_flags_but_never_treats_unreadable_settings_as_direct() {
        let directory =
            std::env::temp_dir().join(format!("nvpn-egress-intent-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("config.toml");
        let mut app = AppConfig::default();
        app.wireguard_exit.enabled = true;
        app.exit_node_leak_protection = true;
        std::fs::write(&path, toml::to_string_pretty(&app).unwrap()).unwrap();
        assert_eq!(read_desired(&path, None, None).unwrap(), Some(true));
        app.wireguard_exit.enabled = false;
        app.exit_node = "selected-peer".into();
        std::fs::write(&path, toml::to_string_pretty(&app).unwrap()).unwrap();
        assert_eq!(read_desired(&path, None, None).unwrap(), Some(true));
        std::fs::write(&path, b"{").unwrap();
        assert!(read_desired(&path, None, Some(true)).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(read_desired(&path, None, Some(true)).is_err());
        assert_eq!(read_desired(&path, None, None).unwrap(), None);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
