use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::SECURE_DNS_PORT;
use nostr_vpn_core::magic_dns::remove_owned_macos_resolver_file;

pub(super) const MACOS_SECURE_DNS_STORE_KEY: &str =
    "State:/Network/Service/to.nostrvpn.nvpn-secure-dns/DNS";

const MACOS_SECURE_DNS_STORE_DICTIONARY: &str = "\
<dictionary> {
  ServerAddresses : <array> {
    0 : 127.0.0.1
  }
  ServerPort : 1053
  SupplementalMatchDomains : <array> {
    0 :
  }
  SupplementalMatchOrders : <array> {
    0 : 1
  }
}";

pub(super) fn macos_resolver_configs() -> [(PathBuf, String); 2] {
    ["nvpn", "fips"].map(|suffix| {
        (
            PathBuf::from("/etc/resolver").join(suffix),
            nostr_vpn_core::magic_dns::macos_secure_dns_resolver_config(),
        )
    })
}

pub(crate) fn cleanup_owned_macos_secure_dns_state() -> anyhow::Result<bool> {
    let mut removed = false;
    let mut failures = Vec::new();
    match remove_owned_macos_secure_dns_store() {
        Ok(was_removed) => removed |= was_removed,
        Err(error) => failures.push(format!("remove {MACOS_SECURE_DNS_STORE_KEY}: {error}")),
    }
    for path in [
        Path::new("/etc/resolver/nvpn-secure-dns"),
        Path::new("/etc/resolver/nvpn"),
        Path::new("/etc/resolver/fips"),
    ] {
        match remove_owned_macos_resolver_file(path, "") {
            Ok(was_removed) => removed |= was_removed,
            Err(error) => failures.push(format!("remove {}: {error}", path.display())),
        }
    }
    if failures.is_empty() {
        Ok(removed)
    } else {
        Err(anyhow::anyhow!(failures.join("; ")))
    }
}

pub(super) fn install_macos_secure_dns_store() -> std::io::Result<()> {
    if let Some(current) = read_macos_secure_dns_store()?
        && !macos_secure_dns_store_contents_owned(&current)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("refusing to replace foreign dynamic-store key {MACOS_SECURE_DNS_STORE_KEY}"),
        ));
    }

    let install = (|| {
        let output = run_scutil(&format!(
            "{}set {MACOS_SECURE_DNS_STORE_KEY}\n",
            macos_secure_dns_store_dictionary_commands()
        ))?;
        if !output.trim().is_empty() {
            return Err(scutil_error("install", &output));
        }
        match read_macos_secure_dns_store()? {
            Some(current) if macos_secure_dns_store_contents_owned(&current) => Ok(()),
            observed => Err(std::io::Error::other(format!(
                "dynamic-store verification failed for {MACOS_SECURE_DNS_STORE_KEY}: {observed:?}"
            ))),
        }
    })();
    if let Err(install_error) = install {
        let rollback = remove_owned_macos_secure_dns_store().and_then(|_| {
            if read_macos_secure_dns_store()?.is_none() {
                Ok(())
            } else {
                Err(std::io::Error::other(
                    "dynamic-store key remains after rollback",
                ))
            }
        });
        return match rollback {
            Ok(_) => Err(install_error),
            Err(rollback_error) => Err(std::io::Error::other(format!(
                "{install_error}; rollback failed: {rollback_error}"
            ))),
        };
    }
    Ok(())
}

pub(super) fn remove_owned_macos_secure_dns_store() -> std::io::Result<bool> {
    match read_macos_secure_dns_store()? {
        None => Ok(false),
        Some(current) if !macos_secure_dns_store_contents_owned(&current) => Ok(false),
        Some(_) => {
            remove_macos_secure_dns_store()?;
            match read_macos_secure_dns_store()? {
                None => Ok(true),
                Some(current) => Err(std::io::Error::other(format!(
                    "dynamic-store key survived cleanup: {current}"
                ))),
            }
        }
    }
}

pub(super) fn macos_secure_dns_store_is_owned() -> std::io::Result<bool> {
    Ok(read_macos_secure_dns_store()?
        .is_some_and(|contents| macos_secure_dns_store_contents_owned(&contents)))
}

fn remove_macos_secure_dns_store() -> std::io::Result<()> {
    let output = run_scutil(&format!("remove {MACOS_SECURE_DNS_STORE_KEY}\n"))?;
    if output.trim().is_empty() {
        Ok(())
    } else {
        Err(scutil_error("remove", &output))
    }
}

fn read_macos_secure_dns_store() -> std::io::Result<Option<String>> {
    let output = run_scutil(&format!("show {MACOS_SECURE_DNS_STORE_KEY}\n"))?;
    let output = output.trim();
    if output == "No such key" {
        Ok(None)
    } else if output.starts_with("<dictionary> {") {
        Ok(Some(output.to_string()))
    } else {
        Err(scutil_error("read", output))
    }
}

fn macos_secure_dns_store_contents_owned(contents: &str) -> bool {
    contents
        .trim()
        .lines()
        .map(str::trim_end)
        .eq(MACOS_SECURE_DNS_STORE_DICTIONARY.lines())
}

fn macos_secure_dns_store_dictionary_commands() -> String {
    format!(
        concat!(
            "d.init\n",
            "d.add ServerAddresses * 127.0.0.1\n",
            "d.add ServerPort # {}\n",
            "d.add SupplementalMatchDomains * \"\"\n",
            "d.add SupplementalMatchOrders * 1\n",
        ),
        SECURE_DNS_PORT
    )
}

fn run_scutil(commands: &str) -> std::io::Result<String> {
    let mut child = Command::new("/usr/sbin/scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("scutil stdin was not piped"))?
        .write_all(commands.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "scutil exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    if !output.stderr.is_empty() {
        return Err(std::io::Error::other(format!(
            "scutil wrote an error: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn scutil_error(action: &str, output: &str) -> std::io::Error {
    std::io::Error::other(format!(
        "scutil failed to {action} {MACOS_SECURE_DNS_STORE_KEY}: {}",
        output.trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_dns_store_uses_the_default_supplemental_match_domain() {
        let commands = macos_secure_dns_store_dictionary_commands();
        assert!(commands.contains("d.add ServerAddresses * 127.0.0.1\n"));
        assert!(commands.contains("d.add ServerPort # 1053\n"));
        assert!(commands.contains("d.add SupplementalMatchDomains * \"\"\n"));
        assert!(!commands.contains("domain ."));
        assert!(macos_secure_dns_store_contents_owned(
            MACOS_SECURE_DNS_STORE_DICTIONARY
        ));
        assert!(!macos_secure_dns_store_contents_owned(
            "<dictionary> {\n  ServerAddresses : 192.0.2.53\n}"
        ));
    }
}
