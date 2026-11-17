#[cfg(test)]
mod update_stripe_tests {
    use super::*;
    use nostr_vpn_app_core::desktop_update::{
        DesktopPlatform, UpdateFailure, UpdateSnapshot, UpdateStep, desktop_update_view,
    };

    const TEST: &str = "update_stripe_tests::the_stripe_shows_each_install_step_and_failures_with_retry";

    fn labels(widget: &gtk::Widget, out: &mut Vec<String>) {
        if let Some(label) = widget.downcast_ref::<gtk::Label>() {
            out.push(label.text().to_string());
        }
        let mut child = widget.first_child();
        while let Some(widget) = child {
            labels(&widget, out);
            child = widget.next_sibling();
        }
    }

    fn progress_fraction(widget: &gtk::Widget) -> Option<f64> {
        if let Some(bar) = widget.downcast_ref::<gtk::ProgressBar>() {
            return Some(bar.fraction());
        }
        let mut child = widget.first_child();
        while let Some(widget) = child {
            if let Some(fraction) = progress_fraction(&widget) {
                return Some(fraction);
            }
            child = widget.next_sibling();
        }
        None
    }

    fn view(step: UpdateStep, download: Option<&str>) -> DesktopUpdateView {
        desktop_update_view(
            &UpdateSnapshot {
                step,
                version: "v4.1.22".to_string(),
                detail: String::new(),
                download: download.map(PathBuf::from),
            },
            DesktopPlatform::Linux,
        )
    }

    /// Render the stripe and return its visible text. With
    /// `NVPN_UPDATE_SHOTS_DIR` set it also saves a PNG of it.
    fn show(app: &AppRef, view: DesktopUpdateView, name: &str) -> (Vec<String>, Option<f64>) {
        apply_update_view(app, view);
        render(app);
        let bar = app.borrow().update_bar.clone();
        let context = glib::MainContext::default();
        let deadline = Instant::now() + Duration::from_millis(150);
        while Instant::now() < deadline {
            context.iteration(false);
        }
        if let Some(dir) = std::env::var_os("NVPN_UPDATE_SHOTS_DIR") {
            let paintable = gtk::WidgetPaintable::new(Some(&bar));
            let snapshot = gtk::Snapshot::new();
            paintable.snapshot(&snapshot, f64::from(bar.width()), f64::from(bar.height()));
            if let (Some(node), Some(renderer)) = (
                snapshot.to_node(),
                bar.native().and_then(|native| native.renderer()),
            ) {
                let path = PathBuf::from(dir).join(format!("{name}.png"));
                renderer.render_texture(&node, None).save_to_png(path).unwrap();
            }
        }
        let mut text = Vec::new();
        labels(bar.upcast_ref(), &mut text);
        (text, progress_fraction(bar.upcast_ref()))
    }

    #[test]
    fn the_stripe_shows_each_install_step_and_failures_with_retry() {
        if std::env::var_os("NVPN_UPDATE_STRIPE_UI_TEST").is_none() {
            let directory =
                std::env::temp_dir().join(format!("nvpn-update-stripe-test-{}", std::process::id()));
            std::fs::create_dir_all(&directory).unwrap();
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env("NVPN_UPDATE_STRIPE_UI_TEST", "1")
                .env("NVPN_APP_DATA_DIR", &directory)
                .env("NVPN_CLI_PATH", "/bin/false")
                .env("G_DEBUG", "fatal-criticals")
                .status();
            std::fs::remove_dir_all(directory).unwrap();
            assert!(result.unwrap().success());
            return;
        }

        adw::init().unwrap();
        let application = adw::Application::new(
            Some("fi.siriusbusiness.nvpn.update-tests"),
            gio::ApplicationFlags::NON_UNIQUE,
        );
        application.register(gio::Cancellable::NONE).unwrap();
        let update_bar = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let window = adw::ApplicationWindow::new(&application);
        let mut model = AppModel::new(
            window.clone(),
            gtk::Box::new(gtk::Orientation::Vertical, 0),
            update_bar.clone(),
            gtk::Box::new(gtk::Orientation::Vertical, 0),
            gtk::Label::new(None),
            gtk::Box::new(gtk::Orientation::Vertical, 0),
            gtk::Switch::new(),
        );
        model.core_ready = true;
        model.state.app_version = "4.1.19".to_string();
        model.update.available = true;
        model.update.version = "v4.1.22".to_string();
        let app = Rc::new(RefCell::new(model));
        window.set_default_size(920, 60);
        window.set_content(Some(&update_bar));
        window.present();

        let (text, _) = show(&app, view(UpdateStep::Idle, None), "01-available");
        assert!(text.contains(&"Update available: v4.1.22 (you're on 4.1.19)".to_string()), "{text:?}");
        assert!(text.contains(&"Download update".to_string()), "{text:?}");

        let (text, bar) = show(&app, view(UpdateStep::Fetching, None), "02-finding");
        assert!(text.contains(&"Finding the update…".to_string()), "{text:?}");
        assert!(bar.is_none() && !text.contains(&"Download update".to_string()));

        let downloading = UpdateStep::Downloading {
            received: 38_000_000,
            total: Some(69_105_401),
        };
        let (text, bar) = show(&app, view(downloading, None), "03-downloading");
        assert!(text.contains(&"Downloading v4.1.22… 55%".to_string()), "{text:?}");
        assert!(bar.is_some_and(|fraction| (fraction - 0.55).abs() < 0.01), "{bar:?}");

        let (text, _) = show(&app, view(UpdateStep::Verifying, None), "04-verifying");
        assert!(text.contains(&"Checking the download…".to_string()), "{text:?}");

        let mut failed = view(UpdateStep::Failed(UpdateFailure::NotFound), None);
        failed.detail = "Update check inconclusive: no current peer observation".to_string();
        let (text, _) = show(&app, failed, "05-failed");
        assert!(
            text.contains(&"Couldn't find a verified copy of the update.".to_string()),
            "{text:?}"
        );
        assert!(text.contains(&"Retry".to_string()) && text.contains(&"Download page".to_string()));

        let package = app.borrow().state.config_path.clone() + ".deb";
        let (text, _) = show(&app, view(UpdateStep::Downloaded, Some(&package)), "06-downloaded");
        assert!(
            text.contains(&"v4.1.22 is downloaded. Install it from the file.".to_string()),
            "{text:?}"
        );
        assert!(text.contains(&"Show download".to_string()), "{text:?}");
    }
}
