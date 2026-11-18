use super::*;
use nix::unistd::{Uid, User};
use serde::Deserialize;
use std::os::unix::fs::MetadataExt;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LaunchDaemon {
    label: String,
    program_arguments: Vec<String>,
}

impl LaunchDaemon {
    fn config(&self, label: &str) -> Result<&Path> {
        let mut configs = self
            .program_arguments
            .windows(2)
            .filter(|pair| pair[0] == "--config");
        if self.label == label
            && self
                .program_arguments
                .get(1)
                .is_some_and(|arg| arg == "daemon")
            && let Some(pair) = configs.next()
            && configs.next().is_none()
            && Path::new(&pair[1]).is_absolute()
        {
            return Ok(Path::new(&pair[1]));
        }
        anyhow::bail!("Could not identify the configuration of launchd service {label}");
    }
}

pub(super) struct InstalledService {
    config: PathBuf,
    pub(super) executable: PathBuf,
}

pub(super) fn installed_service(label: &str) -> Result<Option<InstalledService>> {
    let path = macos_service_plist_path(label);
    let file = match crate::macos_privileged_files::open_artifact(&path) {
        Ok(file) => file,
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|err| err.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(err) => return Err(err).with_context(|| format!("inspect {label}")),
    };
    let job: LaunchDaemon = plist::from_reader(file).with_context(|| format!("read {label}"))?;
    let config = job.config(label)?.to_owned();
    let executable = job
        .program_arguments
        .first()
        .context("missing service executable")?
        .into();
    Ok(Some(InstalledService { config, executable }))
}

pub(crate) struct Registration {
    pub(crate) label: String,
    duplicate: Option<String>,
    pub(crate) executable: Option<PathBuf>,
}

impl Registration {
    pub(super) fn remove_duplicate(self) -> Result<String> {
        if let Some(label) = self.duplicate {
            remove_registration(&label)?;
        }
        Ok(self.label)
    }

    pub(crate) fn for_config(path: &Path) -> Result<Self> {
        let config = canonicalize_lossy(path);
        Self::resolve(&config, installed_service, || {
            // Authorization Services and sudo may both change the current home.
            // A fresh install of a user's main config still gets the standard label.
            if config == canonicalize_lossy(&default_config_path()) {
                return true;
            }
            let standard = Path::new("Library/Application Support/nvpn/config.toml");
            config.ends_with(standard)
                && fs::metadata(&config)
                    .ok()
                    .and_then(|m| User::from_uid(Uid::from_raw(m.uid())).ok().flatten())
                    .is_some_and(|owner| canonicalize_lossy(&owner.dir.join(standard)) == config)
        })
    }

    fn resolve(
        config: &Path,
        read: impl Fn(&str) -> Result<Option<InstalledService>>,
        is_default: impl FnOnce() -> bool,
    ) -> Result<Self> {
        let scoped = macos_scoped_service_label(config);
        let primary = read(MACOS_SERVICE_LABEL)?;
        let hashed = read(&scoped)?;
        if hashed.as_ref().is_some_and(|job| job.config != config) {
            anyhow::bail!("Service {scoped} belongs to a different configuration");
        }
        if let Some(job) = primary.as_ref().filter(|job| job.config == config) {
            if hashed
                .as_ref()
                .is_some_and(|job| job.executable != macos_service_binary_path(&scoped))
            {
                anyhow::bail!("Cannot safely remove the duplicate background service {scoped}");
            }
            return Ok(Self {
                label: MACOS_SERVICE_LABEL.into(),
                executable: Some(job.executable.clone()),
                duplicate: hashed.map(|_| scoped),
            });
        }
        let use_primary = primary.is_none() && hashed.is_none() && is_default();
        Ok(Self {
            label: if use_primary {
                MACOS_SERVICE_LABEL.into()
            } else {
                scoped
            },
            executable: hashed.map(|job| job.executable),
            duplicate: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_registered_config_before_using_the_callers_home() {
        let config = Path::new("/fixture/user/config.toml");
        let other = Path::new("/fixture/other/config.toml");
        let scoped = macos_scoped_service_label(config);
        let read = |primary: Option<&Path>, hashed: Option<&Path>, label: &str| {
            Ok(if label == MACOS_SERVICE_LABEL {
                primary
            } else {
                hashed
            }
            .map(|path| InstalledService {
                config: path.into(),
                executable: macos_service_binary_path(label),
            }))
        };

        for is_default in [false, true] {
            let resolve = |primary, hashed| {
                Registration::resolve(config, |label| read(primary, hashed, label), || is_default)
            };
            let main = resolve(Some(config), None).unwrap();
            assert_eq!(main.label, MACOS_SERVICE_LABEL);
            assert!(main.duplicate.is_none());

            let both = resolve(Some(config), Some(config)).unwrap();
            assert_eq!(both.label, MACOS_SERVICE_LABEL);
            assert_eq!(both.duplicate.as_deref(), Some(scoped.as_str()));

            for primary in [None, Some(other)] {
                let only_scoped = resolve(primary, Some(config)).unwrap();
                assert_eq!(only_scoped.label, scoped);
                assert!(only_scoped.duplicate.is_none());
            }

            let unrelated = resolve(Some(other), None).unwrap();
            assert_eq!(unrelated.label, scoped);
            assert!(unrelated.duplicate.is_none());
            assert!(resolve(Some(config), Some(other)).is_err());

            let new = resolve(None, None).unwrap();
            assert_eq!(
                new.label,
                if is_default {
                    MACOS_SERVICE_LABEL
                } else {
                    &scoped
                }
            );
        }
    }

    #[test]
    fn refuses_to_remove_a_duplicate_with_an_unexpected_executable() {
        let config = Path::new("/fixture/config.toml");
        let registration = Registration::resolve(
            config,
            |_| {
                Ok(Some(InstalledService {
                    config: config.into(),
                    executable: "/fixture/other-tool".into(),
                }))
            },
            || false,
        );
        assert!(registration.is_err());
    }

    #[test]
    fn reads_exact_config_argument_from_generated_launchd_plist() {
        let config = Path::new("/fixture/A & B/config.toml");
        let plist = macos_service_plist_content(
            MACOS_SERVICE_LABEL,
            &macos_service_binary_path(MACOS_SERVICE_LABEL),
            config,
            "utun",
            60,
        );
        let job: LaunchDaemon = plist::from_bytes(plist.as_bytes()).unwrap();
        assert_eq!(job.config(MACOS_SERVICE_LABEL).unwrap(), config);
        assert_eq!(
            Path::new(&job.program_arguments[0]),
            macos_service_binary_path(MACOS_SERVICE_LABEL)
        );
        assert!(job.config("other.service").is_err());
    }
}
