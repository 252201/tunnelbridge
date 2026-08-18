mod agent;
mod commands;
mod config;
mod kcp;
mod runtime;

use std::sync::Arc;

use runtime::RuntimeState;
use tauri::{
    Manager, RunEvent, WindowEvent,
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
};
use tauri_plugin_autostart::MacosLauncher;

pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(
            tauri_plugin_autostart::Builder::new()
                .macos_launcher(MacosLauncher::LaunchAgent)
                .build(),
        )
        .setup(|app| {
            let data_dir = app.path().app_config_dir()?;
            let state = Arc::new(RuntimeState::new(data_dir, app.handle().clone()));
            if let Ok(Some(config)) = config::load_config(&state.config_path()) {
                *state.config.blocking_write() = Some(config);
            }
            app.manage(state.clone());
            setup_tray(app)?;
            if state.config.blocking_read().is_some() {
                agent::restart_agent(state);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_snapshot,
            commands::configure_server,
            commands::create_tunnel,
            commands::update_tunnel,
            commands::delete_tunnel,
            commands::set_all_enabled,
            commands::set_transport_mode,
            commands::get_autostart,
            commands::set_autostart,
            commands::check_for_updates,
            commands::install_update,
        ]);

    let app = builder
        .build(tauri::generate_context!())
        .expect("failed to build TunnelBridge");
    app.run(|handle, event| {
        if let RunEvent::WindowEvent {
            label,
            event: WindowEvent::CloseRequested { api, .. },
            ..
        } = event
            && label == "main"
        {
            api.prevent_close();
            if let Some(window) = handle.get_webview_window("main") {
                let _ = window.hide();
            }
        }
    });
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "打开 TunnelBridge", true, None::<&str>)?;
    let start = MenuItem::with_id(app, "start_all", "启动全部隧道", true, None::<&str>)?;
    let stop = MenuItem::with_id(app, "stop_all", "停止全部隧道", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &start, &stop, &quit])?;
    let mut tray = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .tooltip("TunnelBridge — 正在启动");
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.on_menu_event(|app, event| match event.id.as_ref() {
        "show" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }
        "start_all" | "stop_all" => {
            let enabled = event.id.as_ref() == "start_all";
            let state = app.state::<Arc<RuntimeState>>().inner().clone();
            tauri::async_runtime::spawn(async move {
                let _ = commands::set_all_enabled_inner(state, enabled).await;
            });
        }
        "quit" => app.exit(0),
        _ => {}
    })
    .build(app)?;
    Ok(())
}
