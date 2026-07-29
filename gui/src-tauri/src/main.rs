#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    fs::{create_dir_all, OpenOptions},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tauri::{AppHandle, Manager, RunEvent, Wry};
use tauri_plugin_shell::{
    process::{CommandChild, CommandEvent},
    ShellExt,
};

const MANAGED_PORT_START: u16 = 10101;
const MANAGED_PORT_END: u16 = 10120;
const PROTECTED_HOME_PORT_END: u16 = 10120;
const SUNSHINE_PORT_START: u16 = 47984;
const INITIAL_READY_TIMEOUT: Duration = Duration::from_secs(12);
const HEALTH_INTERVAL: Duration = Duration::from_secs(1);
const RESTART_BACKOFF: Duration = Duration::from_secs(2);

#[derive(Default)]
struct RuntimeState {
    child: Mutex<Option<CommandChild>>,
    status: Mutex<ManagedRuntimeStatus>,
    shutting_down: AtomicBool,
}

#[derive(Clone)]
struct ManagedRuntimeStatus {
    state: &'static str,
    owned: bool,
    pid: Option<u32>,
    port: Option<u16>,
}

impl Default for ManagedRuntimeStatus {
    fn default() -> Self {
        Self {
            state: "starting",
            owned: false,
            pid: None,
            port: None,
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerPrepareRequest {
    public_host: String,
    port: u16,
}

enum ProxyProbe {
    Empty,
    Occupied,
    Compatible(u32),
}

fn cocodex_state_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COCODEX_HOME").filter(|value| !value.is_empty()) {
        return PathBuf::from(root);
    }
    if let Some(profile) = std::env::var_os("USERPROFILE").filter(|value| !value.is_empty()) {
        return PathBuf::from(profile).join(".cocodex");
    }
    std::env::temp_dir().join("CoCodex")
}

fn server_state_root() -> PathBuf {
    cocodex_state_root().with_file_name(".cocodex-server")
}

fn managed_runtime_state_root() -> PathBuf {
    cocodex_state_root().join("runtime").join("opencodex")
}

fn managed_address(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn managed_port_is_allowed(port: u16) -> bool {
    (MANAGED_PORT_START..=MANAGED_PORT_END).contains(&port)
}

fn first_available_managed_port(after: Option<u16>) -> Option<u16> {
    let count = MANAGED_PORT_END - MANAGED_PORT_START + 1;
    let first_offset = after
        .filter(|port| managed_port_is_allowed(*port))
        .map(|port| (port - MANAGED_PORT_START + 1) % count)
        .unwrap_or(0);
    (0..count).find_map(|step| {
        let port = MANAGED_PORT_START + (first_offset + step) % count;
        TcpListener::bind(managed_address(port))
            .ok()
            .map(|listener| {
                drop(listener);
                port
            })
    })
}
fn runtime_log_path() -> PathBuf {
    cocodex_state_root()
        .join("logs")
        .join("desktop-runtime.log")
}

fn sanitize_runtime_detail(value: &str) -> String {
    let mut sanitized = value.replace(['\r', '\n'], " ");
    if let Some(profile) =
        std::env::var_os("USERPROFILE").and_then(|value| value.into_string().ok())
    {
        sanitized = sanitized.replace(&profile, "%USERPROFILE%");
    }
    sanitized.chars().take(768).collect()
}

fn desktop_log(message: &str) {
    let path = runtime_log_path();
    if let Some(parent) = path.parent() {
        let _ = create_dir_all(parent);
    }
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let _ = writeln!(file, "[{timestamp}] {}", sanitize_runtime_detail(message));
}

fn compatible_health_pid(response: &str, expected_port: u16) -> Option<u32> {
    let (headers, body) = response.split_once("\r\n\r\n")?;
    let status = headers.lines().next()?;
    if status != "HTTP/1.1 200 OK" && status != "HTTP/1.0 200 OK" {
        return None;
    }

    let Ok(value) = serde_json::from_str::<serde_json::Value>(body.trim()) else {
        return None;
    };
    let compatible = value.get("status").and_then(|value| value.as_str()) == Some("ok")
        && value.get("service").and_then(|value| value.as_str()) == Some("opencodex")
        && value.get("port").and_then(|value| value.as_u64()) == Some(u64::from(expected_port));
    if !compatible {
        return None;
    }
    value
        .get("pid")
        .and_then(|value| value.as_u64())
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
}

fn probe_proxy(port: u16) -> ProxyProbe {
    let address = managed_address(port);
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(500)) else {
        return ProxyProbe::Empty;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(700)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(700)));

    if stream
        .write_all(
            format!("GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .is_err()
    {
        return ProxyProbe::Occupied;
    }

    let mut response = String::new();
    if stream
        .take(64 * 1024)
        .read_to_string(&mut response)
        .is_err()
    {
        return ProxyProbe::Occupied;
    }
    compatible_health_pid(&response, port)
        .map(ProxyProbe::Compatible)
        .unwrap_or(ProxyProbe::Occupied)
}

fn owned_runtime_pid(state: &RuntimeState) -> Option<u32> {
    state
        .child
        .lock()
        .ok()
        .and_then(|owned| owned.as_ref().map(CommandChild::pid))
}

fn set_runtime_status(
    state: &RuntimeState,
    status: &'static str,
    owned: bool,
    pid: Option<u32>,
    port: Option<u16>,
) {
    if let Ok(mut current) = state.status.lock() {
        *current = ManagedRuntimeStatus {
            state: status,
            owned,
            pid,
            port,
        };
    }
}

fn kill_owned_child(state: &RuntimeState) {
    if let Ok(mut owned) = state.child.lock() {
        if let Some(child) = owned.take() {
            let _ = child.kill();
        }
    }
}

#[tauri::command]
fn managed_runtime_status(state: tauri::State<'_, RuntimeState>) -> serde_json::Value {
    let status = state
        .status
        .lock()
        .ok()
        .map(|status| status.clone())
        .unwrap_or_else(|| ManagedRuntimeStatus {
            state: "error",
            owned: false,
            pid: None,
            port: None,
        });
    serde_json::json!({
        "state": status.state,
        "owned": status.owned,
        "pid": status.pid,
        "port": status.port,
        "baseUrl": status.port.map(|port| format!("http://127.0.0.1:{port}")),
    })
}

fn server_port_is_protected(port: u16) -> bool {
    (10100..=PROTECTED_HOME_PORT_END).contains(&port)
        || (SUNSHINE_PORT_START..=48010).contains(&port)
}

fn server_port_is_available(port: u16) -> bool {
    let Ok(wildcard) = TcpListener::bind(("0.0.0.0", port)) else {
        return false;
    };
    drop(wildcard);
    let Ok(loopback) = TcpListener::bind(("127.0.0.1", port)) else {
        return false;
    };
    drop(loopback);
    true
}

fn validate_server_prepare(request: &ServerPrepareRequest) -> Result<(String, u16), String> {
    let host = request.public_host.trim();
    if host.is_empty() || host.len() > 253 {
        return Err("Enter a public hostname or IP address.".into());
    }
    if !host
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || ".-:[]".contains(character))
    {
        return Err("The public host must be a hostname or IP address, not a URL.".into());
    }
    if request.port < 1024 {
        return Err("Choose a server port between 1024 and 65535.".into());
    }
    if server_port_is_protected(request.port) {
        return Err("That port is reserved for OpenCodex, CoCodex runtime, or Sunshine.".into());
    }
    Ok((host.to_string(), request.port))
}

fn append_server_state_root(args: &mut Vec<String>) {
    args.push("--state-root".into());
    args.push(server_state_root().to_string_lossy().into_owned());
}

async fn run_server_command(app: &AppHandle<Wry>, mut args: Vec<String>) -> Result<String, String> {
    append_server_state_root(&mut args);
    let output = app
        .shell()
        .sidecar("cocodex-server")
        .map_err(|error| format!("could not resolve bundled CoCodex Server: {error}"))?
        .args(args)
        .env("COCODEX_DESKTOP_SERVER_MANAGED", "1")
        .output()
        .await
        .map_err(|error| format!("could not run bundled CoCodex Server: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !output.status.success() {
        let detail = sanitize_runtime_detail(&String::from_utf8_lossy(&output.stderr));
        return Err(if detail.is_empty() {
            "CoCodex Server command failed.".into()
        } else {
            detail
        });
    }
    Ok(stdout)
}

async fn run_server_json(
    app: &AppHandle<Wry>,
    args: Vec<String>,
) -> Result<serde_json::Value, String> {
    let output = run_server_command(app, args).await?;
    serde_json::from_str(&output)
        .map_err(|_| "CoCodex Server returned an invalid response.".to_string())
}

fn safe_server_status(status: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "initialized": status.get("initialized").and_then(|value| value.as_bool()).unwrap_or(false),
        "running": status.get("running").and_then(|value| value.as_bool()).unwrap_or(false),
        "pid": status.get("pid").and_then(|value| value.as_u64()),
        "publicHost": status.get("publicHost").and_then(|value| value.as_str()),
        "port": status.get("port").and_then(|value| value.as_u64()),
        "authority": status.get("authority").and_then(|value| value.as_str()),
        "serverFingerprint": status.get("serverFingerprint").and_then(|value| value.as_str()),
        "database": status.get("database").cloned().unwrap_or(serde_json::Value::Null),
    })
}

#[tauri::command]
async fn desktop_server_status(app: AppHandle<Wry>) -> Result<serde_json::Value, String> {
    let status = run_server_json(&app, vec!["status".into()]).await?;
    Ok(safe_server_status(&status))
}

#[tauri::command]
async fn desktop_server_prepare(
    app: AppHandle<Wry>,
    request: ServerPrepareRequest,
) -> Result<serde_json::Value, String> {
    let (public_host, port) = validate_server_prepare(&request)?;
    let initial_status = run_server_json(&app, vec!["status".into()]).await?;
    let initialized = initial_status
        .get("initialized")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let mut setup = serde_json::Value::Null;

    if !initialized {
        if !server_port_is_available(port) {
            return Err(
                "The selected server port is already in use; no server state was changed.".into(),
            );
        }
        setup = run_server_json(
            &app,
            vec![
                "init".into(),
                "--public-host".into(),
                public_host,
                "--port".into(),
                port.to_string(),
            ],
        )
        .await?;
    }

    let status = run_server_json(&app, vec!["status".into()]).await?;
    if !status
        .get("running")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        run_server_json(&app, vec!["restart".into()]).await?;
    }
    let invitation = run_server_command(
        &app,
        vec!["invite".into(), "--host".into(), "127.0.0.1".into()],
    )
    .await?;
    if invitation.is_empty() || invitation.len() > 16 * 1024 {
        return Err("CoCodex Server returned an invalid invitation.".into());
    }
    let final_status = run_server_json(&app, vec!["status".into()]).await?;
    Ok(serde_json::json!({
        "initializedNow": !initialized,
        "status": safe_server_status(&final_status),
        "invitation": invitation,
        "network": {
            "firewall": setup.get("firewall").cloned().unwrap_or(serde_json::Value::Null),
            "portMapping": setup.get("portMapping").cloned().unwrap_or(serde_json::Value::Null),
            "diagnostic": setup.get("networkDiagnostic").cloned().unwrap_or(serde_json::Value::Null),
            "manualPortForwarding": setup.get("manualPortForwarding").cloned().unwrap_or(serde_json::Value::Null),
        },
    }))
}

#[tauri::command]
async fn desktop_server_bootstrap_approve(
    app: AppHandle<Wry>,
    fingerprint: String,
) -> Result<serde_json::Value, String> {
    let normalized = fingerprint.trim().to_ascii_uppercase();
    let valid = normalized.len() == 79
        && normalized.split('-').count() == 16
        && normalized.split('-').all(|group| {
            group.len() == 4 && group.chars().all(|character| character.is_ascii_hexdigit())
        });
    if !valid {
        return Err("The enrolled device fingerprint is invalid.".into());
    }
    run_server_json(
        &app,
        vec![
            "bootstrap-approve".into(),
            "--fingerprint".into(),
            normalized,
        ],
    )
    .await?;
    Ok(serde_json::json!({ "approved": true }))
}

fn spawn_owned_runtime(app: &AppHandle<Wry>, port: u16) -> Result<(), String> {
    let state = app.state::<RuntimeState>();
    if state.shutting_down.load(Ordering::SeqCst) {
        return Err("desktop is shutting down".into());
    }

    let cocodex_home = cocodex_state_root();
    let opencodex_home = managed_runtime_state_root();
    create_dir_all(&opencodex_home)
        .map_err(|error| format!("could not create isolated runtime state: {error}"))?;
    let port_arg = port.to_string();

    let (mut events, child) = app
        .shell()
        .sidecar("cocodex-runtime")
        .map_err(|error| format!("could not resolve bundled runtime: {error}"))?
        .args(["start", "--port", port_arg.as_str()])
        .env("OCX_SERVICE", "1")
        .env("COCODEX_DESKTOP_MANAGED", "1")
        .env("COCODEX_HOME", &cocodex_home)
        .env("OPENCODEX_HOME", &opencodex_home)
        .spawn()
        .map_err(|error| format!("could not start bundled runtime: {error}"))?;
    let child_pid = child.pid();

    {
        let mut owned = state
            .child
            .lock()
            .map_err(|_| "runtime ownership lock was poisoned".to_string())?;
        if state.shutting_down.load(Ordering::SeqCst) {
            let _ = child.kill();
            return Err("desktop is shutting down".into());
        }
        *owned = Some(child);
    }

    // Both pipes must be drained for the child to remain able to report
    // diagnostics. Output is intentionally discarded here because it can
    // contain provider names or local filesystem paths.
    desktop_log(&format!(
        "started bundled runtime pid={child_pid} port={port}"
    ));
    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                CommandEvent::Stderr(line) => desktop_log(&format!(
                    "runtime stderr: {}",
                    String::from_utf8_lossy(&line)
                )),
                CommandEvent::Error(error) => desktop_log(&format!("runtime event error: {error}")),
                CommandEvent::Terminated(payload) => desktop_log(&format!(
                    "runtime exited code={:?} signal={:?}",
                    payload.code, payload.signal
                )),
                CommandEvent::Stdout(_) => {}
                _ => {}
            }
        }
    });
    Ok(())
}

fn stop_owned_runtime(app: &AppHandle<Wry>) {
    let state = app.state::<RuntimeState>();
    state.shutting_down.store(true, Ordering::SeqCst);
    kill_owned_child(&state);
    set_runtime_status(&state, "stopped", false, None, None);
}

fn show_main_window(app: &AppHandle<Wry>) {
    if let Some(window) = app.get_webview_window("main") {
        // Keep the native desktop surface chat-first while leaving the
        // browser-hosted administration GUI's dashboard default unchanged.
        let _ = window.eval("window.location.hash = '#cocodex';");
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn supervise_runtime(app: AppHandle<Wry>) {
    let mut window_shown = false;
    let initial_deadline = Instant::now() + INITIAL_READY_TIMEOUT;
    let mut selected_port = first_available_managed_port(None);

    loop {
        let state = app.state::<RuntimeState>();
        if state.shutting_down.load(Ordering::SeqCst) {
            return;
        }

        let Some(port) = selected_port else {
            set_runtime_status(&state, "unavailable", false, None, None);
            if !window_shown {
                desktop_log("all dedicated CoCodex runtime ports are occupied");
                show_main_window(&app);
                window_shown = true;
            }
            thread::sleep(RESTART_BACKOFF);
            selected_port = first_available_managed_port(None);
            continue;
        };

        match probe_proxy(port) {
            ProxyProbe::Compatible(pid) if owned_runtime_pid(&state) == Some(pid) => {
                set_runtime_status(&state, "ready", true, Some(pid), Some(port));
                if !window_shown {
                    desktop_log(&format!("owned runtime is ready pid={pid} port={port}"));
                    show_main_window(&app);
                    window_shown = true;
                }
                thread::sleep(HEALTH_INTERVAL);
                continue;
            }
            ProxyProbe::Compatible(pid) => {
                kill_owned_child(&state);
                desktop_log(&format!(
                    "foreign compatible runtime rejected pid={pid} port={port}; selecting another dedicated port"
                ));
                selected_port = first_available_managed_port(Some(port));
                set_runtime_status(&state, "starting", false, None, selected_port);
                continue;
            }
            ProxyProbe::Occupied => {
                kill_owned_child(&state);
                desktop_log(&format!(
                    "foreign or incompatible listener rejected port={port}; selecting another dedicated port"
                ));
                selected_port = first_available_managed_port(Some(port));
                set_runtime_status(&state, "starting", false, None, selected_port);
                continue;
            }
            ProxyProbe::Empty => {}
        }

        kill_owned_child(&state);
        set_runtime_status(&state, "starting", false, None, Some(port));
        if let Err(error) = spawn_owned_runtime(&app, port) {
            desktop_log(&error);
            eprintln!("CoCodex desktop runtime: {error}");
        }

        let attempt_deadline = Instant::now() + INITIAL_READY_TIMEOUT;
        while Instant::now() < attempt_deadline {
            if app
                .state::<RuntimeState>()
                .shutting_down
                .load(Ordering::SeqCst)
            {
                return;
            }
            match probe_proxy(port) {
                ProxyProbe::Compatible(pid) if owned_runtime_pid(&state) == Some(pid) => {
                    set_runtime_status(&state, "ready", true, Some(pid), Some(port));
                    break;
                }
                ProxyProbe::Compatible(pid) => {
                    kill_owned_child(&state);
                    desktop_log(&format!(
                        "listener won startup race pid={pid} port={port}; refusing adoption"
                    ));
                    selected_port = first_available_managed_port(Some(port));
                    set_runtime_status(&state, "starting", false, None, selected_port);
                    break;
                }
                ProxyProbe::Occupied => {
                    kill_owned_child(&state);
                    desktop_log(&format!(
                        "listener won startup race port={port}; refusing adoption"
                    ));
                    selected_port = first_available_managed_port(Some(port));
                    set_runtime_status(&state, "starting", false, None, selected_port);
                    break;
                }
                ProxyProbe::Empty => {}
            }
            thread::sleep(Duration::from_millis(200));
        }

        let ready = matches!(
            probe_proxy(port),
            ProxyProbe::Compatible(pid) if owned_runtime_pid(&state) == Some(pid)
        );
        if ready {
            selected_port = Some(port);
        }
        if !window_shown && (ready || Instant::now() >= initial_deadline) {
            if !ready {
                set_runtime_status(&state, "unavailable", false, None, selected_port);
                desktop_log("runtime readiness timed out; showing disconnected interface");
            }
            show_main_window(&app);
            window_shown = true;
        }

        if !ready {
            thread::sleep(RESTART_BACKOFF);
        }
    }
}
fn main() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .manage(RuntimeState::default())
        .invoke_handler(tauri::generate_handler![
            managed_runtime_status,
            desktop_server_status,
            desktop_server_prepare,
            desktop_server_bootstrap_approve
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            thread::spawn(move || supervise_runtime(handle));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building CoCodex desktop application");

    app.run(|app, event| {
        if matches!(event, RunEvent::Exit) {
            stop_owned_runtime(app);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{
        compatible_health_pid, first_available_managed_port, managed_address,
        managed_port_is_allowed, sanitize_runtime_detail, server_port_is_available,
        server_port_is_protected, validate_server_prepare, ServerPrepareRequest, TcpListener,
        MANAGED_PORT_END, MANAGED_PORT_START,
    };

    #[test]
    fn accepts_only_the_expected_loopback_runtime_identity() {
        let valid = concat!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n",
            "{\"status\":\"ok\",\"service\":\"opencodex\",\"port\":10101,\"pid\":4242}"
        );
        assert_eq!(compatible_health_pid(valid, 10101), Some(4242));
        assert_eq!(compatible_health_pid(valid, 10102), None);

        let wrong_service = concat!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n",
            "{\"status\":\"ok\",\"service\":\"other\",\"port\":10101,\"pid\":4242}"
        );
        assert_eq!(compatible_health_pid(wrong_service, 10101), None);

        let wrong_port = concat!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n",
            "{\"status\":\"ok\",\"service\":\"opencodex\",\"port\":10100,\"pid\":4242}"
        );
        assert_eq!(compatible_health_pid(wrong_port, 10101), None);
        assert_eq!(
            compatible_health_pid(
                "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"ok\",\"service\":\"opencodex\",\"port\":10101}",
                10101,
            ),
            None
        );
        assert_eq!(
            compatible_health_pid("HTTP/1.1 200 OK\r\n\r\nnot-json", 10101),
            None
        );
    }

    #[test]
    fn dedicated_range_never_includes_the_protected_home_port() {
        assert!(!managed_port_is_allowed(10100));
        assert!(managed_port_is_allowed(MANAGED_PORT_START));
        assert!(managed_port_is_allowed(MANAGED_PORT_END));
        assert!(!managed_port_is_allowed(MANAGED_PORT_END + 1));
    }

    #[test]
    fn skips_an_occupied_dedicated_port_without_touching_its_listener() {
        let first =
            first_available_managed_port(None).expect("test requires one free managed port");
        let listener =
            TcpListener::bind(managed_address(first)).expect("selected managed port stays free");
        let next =
            first_available_managed_port(None).expect("test requires a second free managed port");
        assert_ne!(next, first);
        drop(listener);
    }

    #[test]
    fn keeps_runtime_diagnostics_single_line_and_bounded() {
        let detail = format!("first\r\nsecond {}", "x".repeat(900));
        let sanitized = sanitize_runtime_detail(&detail);
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\n'));
        assert_eq!(sanitized.chars().count(), 768);
    }

    #[test]
    fn server_setup_rejects_runtime_and_sunshine_ports() {
        for port in [
            10100, 10101, 10120, 47984, 47989, 47990, 47998, 47999, 48000, 48010,
        ] {
            assert!(server_port_is_protected(port));
        }
        assert!(!server_port_is_protected(19463));
    }

    #[test]
    fn server_setup_accepts_only_structured_hosts_and_unprotected_ports() {
        let valid = ServerPrepareRequest {
            public_host: "cocodex.example.net".into(),
            port: 19463,
        };
        assert_eq!(
            validate_server_prepare(&valid),
            Ok(("cocodex.example.net".into(), 19463))
        );
        for host in ["", "https://example.net", "example.net/path", "host name"] {
            assert!(validate_server_prepare(&ServerPrepareRequest {
                public_host: host.into(),
                port: 19463,
            })
            .is_err());
        }
        assert!(validate_server_prepare(&ServerPrepareRequest {
            public_host: "127.0.0.1".into(),
            port: 10100,
        })
        .is_err());
    }
    #[test]
    fn server_setup_refuses_an_occupied_port_before_initialization() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve server test port");
        let port = listener.local_addr().expect("read reserved port").port();
        assert!(!server_port_is_available(port));
        drop(listener);
        assert!(server_port_is_available(port));
    }
}
