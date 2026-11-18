#[derive(Debug, clap::Args)]
struct FileArgs {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: FileAction,
}

#[derive(Debug, clap::Subcommand)]
enum FileAction {
    /// Send selected files to a device ID (npub or public-key hex).
    Send {
        device: String,
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Show incoming offers and transfer progress.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Accept an incoming offer into the app's received-files folder.
    Accept {
        id: String,
    },
    Decline {
        id: String,
    },
    Cancel {
        id: String,
    },
    Resume {
        id: String,
    },
}

fn run_file_command(args: FileArgs) -> Result<()> {
    use nostr_vpn_core::file_transfers::{self, FileCommand};
    let config = args.config.unwrap_or_else(default_config_path);
    let command = match args.command {
        FileAction::Send { device, files } => {
            file_transfers::validate_recipient(&config, &device)?;
            if files.is_empty() || files.len() > 32 {
                return Err(anyhow!("Choose between 1 and 32 files"));
            }
            let mut staged = Vec::new();
            for file in files {
                match file_transfers::stage_source(&config, &file) {
                    Ok(path) => staged.push(path),
                    Err(error) => {
                        for path in staged {
                            let _ = file_transfers::discard_staged(&config, &path);
                        }
                        return Err(error);
                    }
                }
            }
            let paths = staged
                .into_iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect();
            FileCommand::Send {
                npub: device,
                paths,
            }
        }
        FileAction::List { json } => {
            let transfers = file_transfers::read_state(&config)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&transfers)?);
            } else {
                for transfer in transfers {
                    println!(
                        "{}  {}  {}/{} bytes  {}",
                        transfer.id,
                        transfer.status,
                        transfer.transferred_bytes,
                        transfer.total_bytes,
                        if transfer.peer_name.is_empty() {
                            &transfer.peer_npub
                        } else {
                            &transfer.peer_name
                        }
                    );
                    for file in transfer.files {
                        if let Some(path) = file.local_path {
                            println!("  {path}");
                        }
                    }
                    if let Some(error) = transfer.error {
                        println!("  {error}");
                    }
                }
            }
            return Ok(());
        }
        FileAction::Accept { id } => FileCommand::Accept { id },
        FileAction::Decline { id } => FileCommand::Decline { id },
        FileAction::Cancel { id } => FileCommand::Cancel { id },
        FileAction::Resume { id } => FileCommand::Resume { id },
    };
    let id = match file_transfers::enqueue(&config, command.clone()) {
        Ok(id) => id,
        Err(error) => {
            if let FileCommand::Send { paths, .. } = command {
                for path in paths {
                    let _ = file_transfers::discard_staged(&config, std::path::Path::new(&path));
                }
            }
            return Err(error);
        }
    };
    println!("Queued {id}. Use nvpn file list to follow progress.");
    Ok(())
}
