type WalletReply<T> = std::sync::mpsc::SyncSender<Result<T>>;

#[derive(Debug)]
enum PaidRouteWalletCommand {
    Overview {
        refresh_quotes: bool,
        reply: WalletReply<cashu_service::CashuWalletOverview>,
    },
    Activity {
        reply: WalletReply<Vec<cashu_service::CashuWalletActivityEntry>>,
    },
    CreateTopupQuote {
        mint_url: String,
        amount_sat: u64,
        reply: WalletReply<cashu_service::CashuTopupQuote>,
    },
    ReceiveToken {
        token: String,
        reply: WalletReply<cashu_service::CashuReceivedPayment>,
    },
    SendToken {
        mint_url: String,
        amount_sat: u64,
        reply: WalletReply<cashu_service::CashuSentPayment>,
    },
    PayLightning {
        mint_url: String,
        invoice: String,
        reply: WalletReply<cashu_service::CashuLightningPayment>,
    },
    OpenSpilmanChannel {
        request: cashu_service::StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
        reply: WalletReply<
            cashu_service::StreamingRouteOpenCashuSpilmanChannelFromWalletResult,
        >,
    },
}

#[derive(Debug)]
pub(super) struct PaidRouteWalletRuntime {
    commands: Option<std::sync::mpsc::Sender<PaidRouteWalletCommand>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl PaidRouteWalletRuntime {
    pub(super) fn open(config_path: &Path) -> Result<Self> {
        let config_path = config_path.to_path_buf();
        let (commands, receiver) = std::sync::mpsc::channel();
        let (startup_sender, startup_receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("nvpn-cashu-wallet".to_string())
            .spawn(move || wallet_worker(&config_path, &receiver, &startup_sender))
            .context("failed to start the Cashu wallet worker")?;

        match startup_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                commands: Some(commands),
                worker: Some(worker),
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(_) => {
                let _ = worker.join();
                Err(anyhow!("Cashu wallet worker stopped during startup"))
            }
        }
    }

    fn request<T>(
        &self,
        command: impl FnOnce(WalletReply<T>) -> PaidRouteWalletCommand,
    ) -> Result<T> {
        let (reply, response) = std::sync::mpsc::sync_channel(1);
        self.commands
            .as_ref()
            .context("Cashu wallet worker is stopped")?
            .send(command(reply))
            .map_err(|_| anyhow!("Cashu wallet worker is stopped"))?;
        response
            .recv()
            .map_err(|_| anyhow!("Cashu wallet worker stopped before replying"))?
    }

    pub(super) fn overview(
        &self,
        refresh_quotes: bool,
    ) -> Result<cashu_service::CashuWalletOverview> {
        self.request(|reply| PaidRouteWalletCommand::Overview {
            refresh_quotes,
            reply,
        })
    }

    pub(super) fn activity(&self) -> Result<Vec<cashu_service::CashuWalletActivityEntry>> {
        self.request(|reply| PaidRouteWalletCommand::Activity { reply })
    }

    pub(super) fn create_topup_quote(
        &self,
        mint_url: &str,
        amount_sat: u64,
    ) -> Result<cashu_service::CashuTopupQuote> {
        self.request(|reply| PaidRouteWalletCommand::CreateTopupQuote {
            mint_url: mint_url.to_string(),
            amount_sat,
            reply,
        })
    }

    pub(super) fn receive_token(
        &self,
        token: &str,
    ) -> Result<cashu_service::CashuReceivedPayment> {
        self.request(|reply| PaidRouteWalletCommand::ReceiveToken {
            token: token.to_string(),
            reply,
        })
    }

    pub(super) fn send_token(
        &self,
        mint_url: &str,
        amount_sat: u64,
    ) -> Result<cashu_service::CashuSentPayment> {
        self.request(|reply| PaidRouteWalletCommand::SendToken {
            mint_url: mint_url.to_string(),
            amount_sat,
            reply,
        })
    }

    pub(super) fn pay_lightning(
        &self,
        mint_url: &str,
        invoice: &str,
    ) -> Result<cashu_service::CashuLightningPayment> {
        self.request(|reply| PaidRouteWalletCommand::PayLightning {
            mint_url: mint_url.to_string(),
            invoice: invoice.to_string(),
            reply,
        })
    }

    pub(super) fn open_spilman_channel(
        &self,
        request: cashu_service::StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
    ) -> Result<cashu_service::StreamingRouteOpenCashuSpilmanChannelFromWalletResult> {
        self.request(|reply| PaidRouteWalletCommand::OpenSpilmanChannel { request, reply })
    }
}

impl Drop for PaidRouteWalletRuntime {
    fn drop(&mut self) {
        self.commands.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn wallet_worker(
    config_path: &Path,
    commands: &std::sync::mpsc::Receiver<PaidRouteWalletCommand>,
    startup: &WalletReply<()>,
) {
    let result = open_wallet_service(config_path);
    let (runtime, service) = match result {
        Ok(wallet) => wallet,
        Err(error) => {
            let _ = startup.send(Err(error));
            return;
        }
    };

    let recovery = runtime.block_on(service.recover_startup_state());
    for warning in recovery.warnings {
        tracing::warn!(warning, "Cashu wallet startup recovery is incomplete");
    }
    if startup.send(Ok(())).is_err() {
        return;
    }

    while let Ok(command) = commands.recv() {
        match command {
            PaidRouteWalletCommand::Overview {
                refresh_quotes,
                reply,
            } => {
                let _ = reply.send(runtime.block_on(service.load_wallet_overview(refresh_quotes)));
            }
            PaidRouteWalletCommand::Activity { reply } => {
                let _ = reply.send(runtime.block_on(service.load_wallet_activity()));
            }
            PaidRouteWalletCommand::CreateTopupQuote {
                mint_url,
                amount_sat,
                reply,
            } => {
                let _ = reply.send(runtime.block_on(
                    service.create_topup_quote(&mint_url, amount_sat),
                ));
            }
            PaidRouteWalletCommand::ReceiveToken { token, reply } => {
                let _ = reply.send(runtime.block_on(service.receive_payment_token(&token)));
            }
            PaidRouteWalletCommand::SendToken {
                mint_url,
                amount_sat,
                reply,
            } => {
                let _ = reply.send(runtime.block_on(
                    service.send_payment_token(&mint_url, amount_sat),
                ));
            }
            PaidRouteWalletCommand::PayLightning {
                mint_url,
                invoice,
                reply,
            } => {
                let _ = reply.send(runtime.block_on(
                    service.send_lightning_payment(&mint_url, &invoice),
                ));
            }
            PaidRouteWalletCommand::OpenSpilmanChannel { request, reply } => {
                let _ = reply.send(runtime.block_on(
                    service.open_streaming_route_cashu_spilman_channel(request),
                ));
            }
        }
    }
}

fn open_wallet_service(
    config_path: &Path,
) -> Result<(tokio::runtime::Runtime, cashu_service::CashuWalletService)> {
    let data_dir = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create the Cashu wallet async runtime")?;

    let service = runtime.block_on(cashu_service::CashuWalletService::open_with_seed_store(
        data_dir,
        std::sync::Arc::new(nostr_vpn_core::PlatformCashuWalletSeedStore::new(
            config_path,
        )),
    ))?;

    Ok((runtime, service))
}
