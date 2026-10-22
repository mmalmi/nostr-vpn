type ActionCompletion = Box<dyn FnOnce(&AppRef, &NativeAppState)>;

struct PendingAction {
    settle_service: bool,
    completion: Option<ActionCompletion>,
}

struct CoreResult {
    is_action: bool,
    state: NativeAppState,
}

fn start_core_worker(
    create: impl FnOnce() -> Arc<FfiApp> + Send + 'static,
) -> (Sender<Option<NativeAppAction>>, Receiver<CoreResult>) {
    let (requests, incoming) = mpsc::channel::<Option<NativeAppAction>>();
    let (outgoing, results) = mpsc::channel();
    std::thread::spawn(move || {
        // Construction also reads daemon/service status and may wait on the CLI.
        let core = create();
        if outgoing
            .send(CoreResult {
                is_action: false,
                state: core.state(),
            })
            .is_err()
        {
            return;
        }
        // Preserve command order without holding GTK's main thread on daemon IPC.
        // Refreshes are coalesced by the UI; only explicit actions can queue.
        while let Ok(action) = incoming.recv() {
            let is_action = action.is_some();
            let state = match action {
                Some(action) => {
                    let autostart = match &action {
                        NativeAppAction::UpdateSettings { patch } => patch.launch_on_startup,
                        _ => None,
                    };
                    match autostart.map(configure_launch_on_startup).transpose() {
                        Ok(_) => core.dispatch(action),
                        Err(error) => {
                            let mut state = core.state();
                            state.error = error;
                            state
                        }
                    }
                }
                None => core.refresh(),
            };
            if outgoing.send(CoreResult { is_action, state }).is_err() {
                break;
            }
        }
    });
    (requests, results)
}

fn refresh_now(app: &AppRef) {
    let failed = {
        let mut model = app.borrow_mut();
        if !model.core_ready || model.refresh_pending || !model.pending_actions.is_empty() {
            return;
        }
        model.refresh_pending = model.core_requests.send(None).is_ok();
        !model.refresh_pending
    };
    if failed {
        core_worker_failed(app);
    }
}

fn dispatch(app: &AppRef, action: NativeAppAction) {
    queue_action(app, action, None);
}

fn dispatch_with_completion(
    app: &AppRef,
    action: NativeAppAction,
    completion: impl FnOnce(&AppRef, &NativeAppState) + 'static,
) {
    queue_action(app, action, Some(Box::new(completion)));
}

fn queue_action(app: &AppRef, action: NativeAppAction, completion: Option<ActionCompletion>) {
    let settle_service = matches!(
        &action,
        NativeAppAction::InstallSystemService
            | NativeAppAction::UninstallSystemService
            | NativeAppAction::EnableSystemService
            | NativeAppAction::DisableSystemService
    );
    let failed = {
        let mut model = app.borrow_mut();
        model.pending_actions.push_back(PendingAction {
            settle_service,
            completion,
        });
        model.core_requests.send(Some(action)).is_err()
    };
    if failed {
        core_worker_failed(app);
    } else {
        render(app);
    }
}

fn drain_core_results(app: &AppRef) {
    loop {
        let result = app.borrow().core_results.try_recv();
        match result {
            Ok(CoreResult {
                is_action: true,
                state,
            }) => {
                let pending = app.borrow_mut().pending_actions.pop_front();
                set_state(app, state.clone());
                render(app);
                if let Some(pending) = pending {
                    if pending.settle_service {
                        start_service_settlement_polling(app);
                    }
                    if let Some(completion) = pending.completion {
                        completion(app, &state);
                    }
                }
            }
            Ok(CoreResult {
                is_action: false,
                state,
            }) => {
                let (initialized, should_render) = {
                    let mut model = app.borrow_mut();
                    let initialized = !model.core_ready;
                    model.core_ready = true;
                    model.refresh_pending = false;
                    if initialized {
                        model.drafts.sync_from_state(&state);
                    }
                    (
                        initialized,
                        initialized
                            || state_needs_render(&model.state, &state)
                            || model.render_pending,
                    )
                };
                set_state(app, state.clone());
                if initialized {
                    sync_launch_on_startup_setting(app);
                    check_updates_if_due(app);
                }
                refresh_live_widgets(app, &state);
                if should_render {
                    let editing = gtk::prelude::GtkWindowExt::focus(&app.borrow().window)
                        .is_some_and(|widget| {
                            widget.is::<gtk::Entry>() || widget.is::<gtk::TextView>()
                        });
                    if editing {
                        app.borrow_mut().render_pending = true;
                    } else {
                        render(app);
                    }
                }
            }
            Err(mpsc::TryRecvError::Empty) => break,
            Err(mpsc::TryRecvError::Disconnected) => {
                let pending = {
                    let model = app.borrow();
                    model.refresh_pending || !model.pending_actions.is_empty()
                };
                if pending {
                    core_worker_failed(app);
                }
                break;
            }
        }
    }
}

fn core_worker_failed(app: &AppRef) {
    let (pending, state) = {
        let mut model = app.borrow_mut();
        model.core_ready = false;
        model.refresh_pending = false;
        model.state.error =
            "App background worker stopped. Reopen the app to continue.".to_string();
        (
            std::mem::take(&mut model.pending_actions),
            model.state.clone(),
        )
    };
    render(app);
    for action in pending {
        if let Some(completion) = action.completion {
            completion(app, &state);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "core_worker_tests.rs"]
mod core_worker_tests;
