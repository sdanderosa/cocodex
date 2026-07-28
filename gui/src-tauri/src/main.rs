#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    fs::{create_dir_all, OpenOptions},
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
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

const PROXY_ADDRESS: &str = "127.0.0.1:10100";
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
}

impl Default for ManagedRuntimeStatus {
    fn default() -> Self {
        Self {
            state: "starting",
            owned: false,
            pid: None,
        }
    }
}

enum ProxyProbe {
    Empty,
    Occupied,
    Compatible(u32),
}

fn runtime_log_path() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("CoCodex")
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

fn compatible_health_pid(response: &str) -> Option<u32> {
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
        && value.get("port").and_then(|value| value.as_u64()) == Some(10100);
    if !compatible {
        return None;
    }
    value
        .get("pid")
        .and_then(|value| value.as_u64())
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
}

fn probe_proxy() -> ProxyProbe {
    let address: SocketAddr = PROXY_ADDRESS.parse().expect("fixed proxy address is valid");
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(500)) else {
        return ProxyProbe::Empty;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(700)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(700)));

    if stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:10100\r\nConnection: close\r\n\r\n")
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
    compatible_health_pid(&response)
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

fn set_runtime_status(state: &RuntimeState, status: &'static str, owned: bool, pid: Option<u32>) {
    if let Ok(mut current) = state.status.lock() {
        *current = ManagedRuntimeStatus {
            state: status,
            owned,
            pid,
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
        });
    serde_json::json!({
        "state": status.state,
        "owned": status.owned,
        "pid": status.pid,
    })
}

fn spawn_owned_runtime(app: &AppHandle<Wry>) -> Result<(), String> {
    let state = app.state::<RuntimeState>();
    if state.shutting_down.load(Ordering::SeqCst) {
        return Err("desktop is shutting down".into());
    }

    let (mut events, child) = app
        .shell()
        .sidecar("cocodex-runtime")
        .map_err(|error| format!("could not resolve bundled runtime: {error}"))?
        .args(["start", "--port", "10100"])
        .env("OCX_SERVICE", "1")
        .env("COCODEX_DESKTOP_MANAGED", "1")
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
    desktop_log(&format!("started bundled runtime pid={child_pid}"));
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
    set_runtime_status(&state, "stopped", false, None);
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
    let mut reported_foreign_pid: Option<Option<u32>> = None;

    loop {
        let state = app.state::<RuntimeState>();
        if state.shutting_down.load(Ordering::SeqCst) {
            return;
        }

        match probe_proxy() {
            ProxyProbe::Compatible(pid) if owned_runtime_pid(&state) == Some(pid) => {
                set_runtime_status(&state, "ready", true, Some(pid));
                reported_foreign_pid = None;
                if !window_shown {
                    desktop_log(&format!("owned runtime is ready pid={pid}"));
                    show_main_window(&app);
                    window_shown = true;
                }
                thread::sleep(HEALTH_INTERVAL);
                continue;
            }
            ProxyProbe::Compatible(pid) => {
                kill_owned_child(&state);
                set_runtime_status(&state, "foreign-listener", false, Some(pid));
                if reported_foreign_pid != Some(Some(pid)) {
                    desktop_log(&format!(
                        "foreign compatible runtime rejected pid={pid}; showing disconnected interface"
                    ));
                    reported_foreign_pid = Some(Some(pid));
                }
                if !window_shown {
                    show_main_window(&app);
                    window_shown = true;
                }
                thread::sleep(HEALTH_INTERVAL);
                continue;
            }
            ProxyProbe::Occupied => {
                kill_owned_child(&state);
                set_runtime_status(&state, "foreign-listener", false, None);
                if reported_foreign_pid != Some(None) {
                    desktop_log(
                        "foreign or incompatible listener rejected; showing disconnected interface",
                    );
                    reported_foreign_pid = Some(None);
                }
                if !window_shown {
                    show_main_window(&app);
                    window_shown = true;
                }
                thread::sleep(HEALTH_INTERVAL);
                continue;
            }
            ProxyProbe::Empty => {
                reported_foreign_pid = None;
            }
        }

        kill_owned_child(&state);
        set_runtime_status(&state, "starting", false, None);
        if let Err(error) = spawn_owned_runtime(&app) {
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
            match probe_proxy() {
                ProxyProbe::Compatible(pid) if owned_runtime_pid(&state) == Some(pid) => {
                    set_runtime_status(&state, "ready", true, Some(pid));
                    break;
                }
                ProxyProbe::Compatible(pid) => {
                    kill_owned_child(&state);
                    set_runtime_status(&state, "foreign-listener", false, Some(pid));
                    break;
                }
                ProxyProbe::Occupied => {
                    kill_owned_child(&state);
                    set_runtime_status(&state, "foreign-listener", false, None);
                    break;
                }
                ProxyProbe::Empty => {}
            }
            thread::sleep(Duration::from_millis(200));
        }

        // Never leave the user with an invisible application if another
        // process owns the port or the bundled runtime cannot initialize.
        let ready = matches!(
            probe_proxy(),
            ProxyProbe::Compatible(pid) if owned_runtime_pid(&state) == Some(pid)
        );
        if !window_shown && (ready || Instant::now() >= initial_deadline) {
            if !ready {
                set_runtime_status(&state, "unavailable", false, None);
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
        .plugin(tauri_plugin_shell::init())
        .manage(RuntimeState::default())
        .invoke_handler(tauri::generate_handler![managed_runtime_status])
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
    use super::{compatible_health_pid, sanitize_runtime_detail};

    #[test]
    fn accepts_only_the_expected_loopback_runtime_identity() {
        let valid = concat!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n",
            "{\"status\":\"ok\",\"service\":\"opencodex\",\"port\":10100,\"pid\":4242}"
        );
        assert_eq!(compatible_health_pid(valid), Some(4242));

        let wrong_service = concat!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n",
            "{\"status\":\"ok\",\"service\":\"other\",\"port\":10100}"
        );
        assert_eq!(compatible_health_pid(wrong_service), None);

        let wrong_port = concat!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n",
            "{\"status\":\"ok\",\"service\":\"opencodex\",\"port\":20200}"
        );
        assert_eq!(compatible_health_pid(wrong_port), None);
        assert_eq!(
            compatible_health_pid(
                "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"ok\",\"service\":\"opencodex\",\"port\":10100}"
            ),
            None
        );
        assert_eq!(
            compatible_health_pid("HTTP/1.1 200 OK\r\n\r\nnot-json"),
            None
        );
    }

    #[test]
    fn keeps_runtime_diagnostics_single_line_and_bounded() {
        let detail = format!("first\r\nsecond {}", "x".repeat(900));
        let sanitized = sanitize_runtime_detail(&detail);
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\n'));
        assert_eq!(sanitized.chars().count(), 768);
    }
}
