use anyhow::Result;
use serde::{Deserialize, Serialize};
use tauri::{
    Manager, Runtime,
    plugin::{PluginHandle, TauriPlugin},
};

const PLUGIN_IDENTIFIER: &str = "to.iris.nvpn.vpn";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartVpnArgs {
    pub session_name: String,
    pub local_addresses: Vec<String>,
    pub routes: Vec<String>,
    pub dns_servers: Vec<String>,
    pub search_domains: Vec<String>,
    pub mtu: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartVpnResponse {
    pub tun_fd: i32,
    pub active: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VpnStatus {
    pub prepared: bool,
    pub active: bool,
    pub error: Option<String>,
}

pub(crate) struct AndroidVpn<R: Runtime> {
    handle: PluginHandle<R>,
}

pub(crate) trait AndroidVpnExt<R: Runtime> {
    fn android_vpn(&self) -> &AndroidVpn<R>;
}

impl<R: Runtime, T: Manager<R>> AndroidVpnExt<R> for T {
    fn android_vpn(&self) -> &AndroidVpn<R> {
        self.state::<AndroidVpn<R>>().inner()
    }
}

impl<R: Runtime> AndroidVpn<R> {
    pub(crate) fn prepare(&self) -> Result<()> {
        #[cfg(target_os = "android")]
        {
            let _ = self
                .handle
                .run_mobile_plugin::<serde_json::Value>("prepare", ())?;
            return Ok(());
        }

        #[cfg(not(target_os = "android"))]
        {
            Err(anyhow::anyhow!(
                "android vpn plugin is unavailable on this platform"
            ))
        }
    }

    pub(crate) fn start(&self, args: &StartVpnArgs) -> Result<StartVpnResponse> {
        #[cfg(target_os = "android")]
        {
            return self
                .handle
                .run_mobile_plugin("start", args)
                .map_err(anyhow::Error::from);
        }

        #[cfg(not(target_os = "android"))]
        {
            let _ = args;
            Err(anyhow::anyhow!(
                "android vpn plugin is unavailable on this platform"
            ))
        }
    }

    pub(crate) fn stop(&self) -> Result<()> {
        #[cfg(target_os = "android")]
        {
            let _ = self
                .handle
                .run_mobile_plugin::<serde_json::Value>("stop", ())?;
            return Ok(());
        }

        #[cfg(not(target_os = "android"))]
        {
            Err(anyhow::anyhow!(
                "android vpn plugin is unavailable on this platform"
            ))
        }
    }

    pub(crate) fn status(&self) -> Result<VpnStatus> {
        #[cfg(target_os = "android")]
        {
            return self
                .handle
                .run_mobile_plugin("status", ())
                .map_err(anyhow::Error::from);
        }

        #[cfg(not(target_os = "android"))]
        {
            Err(anyhow::anyhow!(
                "android vpn plugin is unavailable on this platform"
            ))
        }
    }
}

pub(crate) struct Builder;

impl Builder {
    pub(crate) const fn new() -> Self {
        Self
    }

    pub(crate) fn build<R: Runtime>(self) -> TauriPlugin<R> {
        #[cfg(target_os = "android")]
        {
            tauri::plugin::Builder::<R>::new("android-vpn")
                .setup(|app, api| {
                    let handle =
                        api.register_android_plugin(PLUGIN_IDENTIFIER, "NostrVpnPlugin")?;
                    app.manage(AndroidVpn { handle });
                    Ok(())
                })
                .build()
        }

        #[cfg(not(target_os = "android"))]
        {
            tauri::plugin::Builder::<R>::new("android-vpn").build()
        }
    }
}
