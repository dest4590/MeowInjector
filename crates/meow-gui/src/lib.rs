slint::include_modules!();

mod sound;

#[cfg(target_os = "windows")]
use meow_core::driver::Driver;
use meow_core::process::{ProcessArch, extract_process_icon, list_processes};
use slint::ComponentHandle;
use std::cell::RefCell;
use std::collections::HashMap;
use std::panic::{self, PanicHookInfo};
use std::rc::Rc;
use std::sync::Mutex;

static LAST_CRASH: Mutex<Option<String>> = Mutex::new(None);

fn format_panic(info: &PanicHookInfo) -> String {
    let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    };
    let location = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_else(|| "unknown location".to_string());
    let backtrace = std::backtrace::Backtrace::force_capture();
    format!("message:\n  {payload}\n\nlocation:\n  {location}\n\nbacktrace:\n{backtrace}")
}

fn install_crash_handler(ui_weak: slint::Weak<MainWindow>) {
    let prev = panic::take_hook();
    panic::set_hook(Box::new(move |info: &PanicHookInfo| {
        let detail = format_panic(info);
        if let Ok(mut g) = LAST_CRASH.lock() {
            *g = Some(detail.clone());
        }
        let _ = slint::invoke_from_event_loop({
            let ui_weak = ui_weak.clone();
            let detail = detail.clone();
            move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_crash_title("unexpected crash".into());
                    ui.set_crash_detail(detail.as_str().into());
                    ui.set_crash_open(true);
                }
            }
        });
        prev(info);
    }));
}

fn show_crash_window() {
    let detail = LAST_CRASH
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(|| "unknown crash".to_string());
    if let Ok(window) = MainWindow::new() {
        window.set_disclaimer_open(false);
        window.set_crash_title("unexpected crash".into());
        window.set_crash_detail(detail.as_str().into());
        window.set_crash_open(true);
        window.on_crash_quit(|| {
            let _ = slint::quit_event_loop();
        });
        window.on_crash_dismiss(|| {
            let _ = slint::quit_event_loop();
        });
        let _ = window.run();
    }
}

#[cfg(target_os = "windows")]
const DEVICE_PATH: &str = "\\\\.\\{meow}";

fn config_path() -> std::path::PathBuf {
    let base = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    base.join("meow-injector.conf")
}

fn read_config() -> Vec<(String, String)> {
    std::fs::read_to_string(config_path())
        .map(|s| {
            s.lines()
                .filter_map(|l| {
                    l.split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn write_config(pairs: &[(String, String)]) {
    let content = pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n");
    let _ = std::fs::write(config_path(), content);
}

fn set_config_value(key: &str, value: &str) {
    let mut pairs = read_config();
    if let Some(entry) = pairs.iter_mut().find(|(k, _)| k == key) {
        entry.1 = value.to_string();
    } else {
        pairs.push((key.to_string(), value.to_string()));
    }
    write_config(&pairs);
}

fn get_config_value(key: &str) -> String {
    read_config()
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
        .unwrap_or_default()
}

fn disclaimer_accepted() -> bool {
    get_config_value("disclaimer_accepted") == "1"
}

fn set_disclaimer_accepted() {
    set_config_value("disclaimer_accepted", "1");
}

const MAX_RECENT_DLLS: usize = 5;

fn load_recent_dlls() -> Vec<String> {
    get_config_value("recent_dlls")
        .split('|')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect()
}

fn save_recent_dll(path: &str) -> Vec<String> {
    let mut recents: Vec<String> = load_recent_dlls()
        .into_iter()
        .filter(|p| !p.eq_ignore_ascii_case(path))
        .collect();
    recents.insert(0, path.to_string());
    recents.truncate(MAX_RECENT_DLLS);
    set_config_value("recent_dlls", &recents.join("|"));
    recents
}

fn save_last_process(name: &str) {
    set_config_value("last_process", name);
}

fn load_last_process() -> String {
    get_config_value("last_process")
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Settings {
    close_after_inject: bool,
    auto_map_driver: bool,
    hide_system: bool,
    mute_sound: bool,
    use_manual_map: bool,
    #[serde(default)]
    favorite_dlls: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            close_after_inject: false,
            auto_map_driver: false,
            hide_system: false,
            mute_sound: false,
            use_manual_map: false,
            favorite_dlls: Vec::new(),
        }
    }
}

fn settings_path() -> std::path::PathBuf {
    let base = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    base.join("meow-injector.settings.json")
}

fn load_settings() -> Settings {
    std::fs::read_to_string(settings_path())
        .ok()
        .and_then(|s| serde_json::from_str::<Settings>(&s).ok())
        .unwrap_or_default()
}

fn save_settings(s: &Settings) {
    if let Ok(json) = serde_json::to_string_pretty(s) {
        let _ = std::fs::write(settings_path(), json);
    }
}

const SYSTEM_PROCESSES: &[&str] = &[
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dllhost.exe",
    "fontdrvhost.exe",
    "audiodg.exe",
    "conhost.exe",
    "registry",
    "memory compression",
    "secure system",
    "idle",
    "dwm.exe",
];

fn is_system_process(name: &str) -> bool {
    let n = name.to_lowercase();
    SYSTEM_PROCESSES.iter().any(|s| n == *s)
}

fn arch_to_int(a: ProcessArch) -> i32 {
    match a {
        ProcessArch::X64 => 1,
        ProcessArch::X86 => 2,
        ProcessArch::Unknown => 0,
    }
}

const KDMAPPER_URL: &str =
    "https://github.com/dest4590/MeowInjector/releases/download/0.0.0/kdmapper.exe";
const DRIVER_URL: &str =
    "https://github.com/dest4590/MeowInjector/releases/download/0.0.0/meow_driver.sys";

fn temp_dir() -> std::path::PathBuf {
    std::env::temp_dir().join("meow-injector")
}

fn download_file(url: &str, dest: &std::path::Path) -> Result<(), String> {
    let resp = ureq::get(url)
        .call()
        .map_err(|e| format!("HTTP request failed: {e}"))?;
    let mut reader = resp.into_body().into_reader();
    let mut file = std::fs::File::create(dest).map_err(|e| format!("Cannot create file: {e}"))?;
    std::io::copy(&mut reader, &mut file).map_err(|e| format!("Write failed: {e}"))?;
    Ok(())
}

fn do_map_driver() -> Result<String, String> {
    let dir = temp_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("Cannot create temp dir: {e}"))?;

    let kdmapper_path = dir.join("kdmapper.exe");
    let driver_path = dir.join("meow_driver.sys");

    if !kdmapper_path.exists() {
        download_file(KDMAPPER_URL, &kdmapper_path)?;
    }
    if !driver_path.exists() {
        download_file(DRIVER_URL, &driver_path)?;
    }

    let output = std::process::Command::new(&kdmapper_path)
        .arg(&driver_path)
        .output()
        .map_err(|e| format!("Failed to run kdmapper: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!("kdmapper failed: {stdout}{stderr}"));
    }

    Ok("driver mapped successfully".into())
}

fn apply_dll(ui: &MainWindow, path: &str) {
    let recents = save_recent_dll(path);
    ui.set_recent_dlls(
        recents
            .iter()
            .map(|p| p.as_str().into())
            .collect::<Vec<_>>()
            .as_slice()
            .into(),
    );
    ui.set_dll_path(path.into());
    let short_name = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string());
    ui.set_dll_hint(format!("{short_name}...").into());
    ui.set_status_text("".into());
    ui.set_inject_ready(ui.get_process_pid() > 0);
    ui.set_is_favorite(is_favorite_dll(path));
}

const MAX_FAVORITE_DLLS: usize = 8;

fn is_favorite_dll(path: &str) -> bool {
    load_settings()
        .favorite_dlls
        .iter()
        .any(|p| p.eq_ignore_ascii_case(path))
}

fn file_name_of(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}

fn refresh_favorites_ui(ui: &MainWindow, favs: &[String]) {
    ui.set_favorite_dlls(
        favs.iter()
            .map(|p| p.as_str().into())
            .collect::<Vec<_>>()
            .as_slice()
            .into(),
    );
    ui.set_favorite_names(
        favs.iter()
            .map(|p| file_name_of(p).as_str().into())
            .collect::<Vec<_>>()
            .as_slice()
            .into(),
    );
    let cur = ui.get_dll_path().to_string();
    ui.set_is_favorite(!cur.is_empty() && favs.iter().any(|p| p.eq_ignore_ascii_case(&cur)));
}

/// true while the FACEIT anti-cheat kernel service is running.
/// checked via `sc query faceit` (STATE == RUNNING).
#[cfg(target_os = "windows")]
fn faceit_ac_running() -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    match std::process::Command::new("sc")
        .args(["query", "faceit"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).lines().any(|l| {
            let u = l.to_uppercase();
            u.contains("STATE") && u.contains("RUNNING")
        }),
        _ => false,
    }
}

#[cfg(not(target_os = "windows"))]
fn faceit_ac_running() -> bool {
    false
}

fn apply_filter(
    ui: &MainWindow,
    all: &[(String, u32, ProcessArch)],
    icons: &[slint::Image],
    query: &str,
    settings: &Settings,
) {
    let q = query.to_lowercase();
    let mut names: Vec<slint::SharedString> = Vec::new();
    let mut pids: Vec<i32> = Vec::new();
    let mut indices: Vec<i32> = Vec::new();
    let mut ic: Vec<slint::Image> = Vec::new();
    let mut arch: Vec<i32> = Vec::new();

    for (i, (name, pid, a)) in all.iter().enumerate() {
        if settings.hide_system && is_system_process(name) {
            continue;
        }
        if *a != ProcessArch::X64 {
            continue;
        }
        if !q.is_empty() && !name.to_lowercase().contains(&q) {
            continue;
        }
        names.push(name.as_str().into());
        pids.push(*pid as i32);
        indices.push(i as i32);
        ic.push(icons.get(i).cloned().unwrap_or_default());
        arch.push(arch_to_int(*a));
    }

    ui.set_filtered_names(slint::ModelRc::from(names.as_slice()));
    ui.set_filtered_pids(slint::ModelRc::from(pids.as_slice()));
    ui.set_filtered_indices(slint::ModelRc::from(indices.as_slice()));
    ui.set_filtered_icons(slint::ModelRc::from(ic.as_slice()));
    ui.set_filtered_arch(slint::ModelRc::from(arch.as_slice()));
}

type IconCache = Rc<RefCell<HashMap<String, slint::Image>>>;
type ProcessList = Rc<RefCell<Vec<(String, u32, ProcessArch)>>>;

fn icon_image(pid: u32) -> slint::Image {
    extract_process_icon(pid)
        .map(|(rgba, w, h)| {
            let buf =
                slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(&rgba, w, h);
            slint::Image::from_rgba8(buf)
        })
        .unwrap_or_default()
}

/// list all processes, pulling icons from the cache so only brand new
/// exe names pay for an actual shell icon lookup.
fn snapshot_processes(
    icon_cache: &IconCache,
) -> (Vec<(String, u32, ProcessArch)>, Vec<slint::Image>) {
    let procs = list_processes();
    let mut cache = icon_cache.borrow_mut();
    let icons = procs
        .iter()
        .map(|(name, pid, _)| {
            let key = name.to_ascii_lowercase();
            if let Some(img) = cache.get(&key) {
                return img.clone();
            }
            let img = icon_image(*pid);
            if img.size().width > 0 {
                cache.insert(key, img.clone());
            }
            img
        })
        .collect();
    (procs, icons)
}

/// re-resolve the selected process by name. keeps the remembered name
/// across restarts so a new pid for the same exe gets picked up again.
fn sync_selection(ui: &MainWindow, all: &[(String, u32, ProcessArch)], icons: &[slint::Image]) {
    let name = ui.get_process_name().to_string();
    if name.is_empty() {
        return;
    }

    match all
        .iter()
        .position(|(n, _, _)| n.eq_ignore_ascii_case(&name))
    {
        Some(idx) => {
            let pid = all[idx].1;
            let prev = ui.get_process_pid() as u32;
            ui.set_selected_index(idx as i32);
            ui.set_game_found(true);
            if prev != pid {
                ui.set_process_pid(pid as i32);
                ui.set_process_icon(icons.get(idx).cloned().unwrap_or_default());
                ui.set_inject_ready(!ui.get_dll_path().is_empty() && !ui.get_injecting());
                if !ui.get_injecting() {
                    ui.set_status_ok(true);
                    ui.set_status_text(
                        if prev == 0 {
                            format!("found {name} (pid {pid})")
                        } else {
                            format!("{name} restarted, pid {prev} -> {pid}")
                        }
                        .as_str()
                        .into(),
                    );
                }
            }
        }
        None => {
            ui.set_selected_index(-1);
            ui.set_game_found(false);
            if ui.get_process_pid() != 0 {
                ui.set_process_pid(0);
                ui.set_inject_ready(false);
                if !ui.get_injecting() {
                    ui.set_status_ok(false);
                    ui.set_status_text(format!("{name} not running, waiting...").as_str().into());
                }
            }
        }
    }
}

/// re-snapshot the process list, push it to the ui and re-resolve the
/// current selection by name (picking up new pids in realtime).
fn refresh_process_list(
    ui: &MainWindow,
    all_processes: &ProcessList,
    all_icons: &Rc<RefCell<Vec<slint::Image>>>,
    settings: &Rc<RefCell<Settings>>,
    icon_cache: &IconCache,
) {
    let (procs, icons) = snapshot_processes(icon_cache);

    let changed = {
        let cur = all_processes.borrow();
        cur.len() != procs.len()
            || cur
                .iter()
                .zip(procs.iter())
                .any(|(a, b)| a.0 != b.0 || a.1 != b.1 || a.2 != b.2)
    };

    if changed {
        let names: Vec<slint::SharedString> =
            procs.iter().map(|(n, _, _)| n.as_str().into()).collect();
        let pids: Vec<i32> = procs.iter().map(|(_, p, _)| *p as i32).collect();
        *all_processes.borrow_mut() = procs;
        *all_icons.borrow_mut() = icons;
        ui.set_process_names(slint::ModelRc::from(names.as_slice()));
        ui.set_process_pids(slint::ModelRc::from(pids.as_slice()));

        let s = settings.borrow();
        apply_filter(
            ui,
            &all_processes.borrow()[..],
            &all_icons.borrow()[..],
            ui.get_search_text().as_str(),
            &s,
        );
    }

    sync_selection(ui, &all_processes.borrow()[..], &all_icons.borrow()[..]);
}

#[cfg(target_os = "windows")]
fn is_running_as_admin() -> bool {
    use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(not(target_os = "windows"))]
fn is_running_as_admin() -> bool {
    true
}

#[cfg(target_os = "windows")]
fn restart_as_admin() {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOW;

    if let Ok(exe) = std::env::current_exe() {
        let file: Vec<u16> = exe
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let op: Vec<u16> = "runas\0".encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            ShellExecuteW(
                0 as _,
                windows_sys::core::PCWSTR::from(op.as_ptr()),
                windows_sys::core::PCWSTR::from(file.as_ptr()),
                0 as _,
                0 as _,
                SW_SHOW,
            );
        }
    }
}

pub fn run_gui() {
    let main_window = MainWindow::new().unwrap();
    let audio = sound::Audio::new();

    install_crash_handler(main_window.as_weak());

    main_window.set_not_admin(!is_running_as_admin());
    main_window.set_disclaimer_open(!disclaimer_accepted());

    let all_processes: Rc<RefCell<Vec<(String, u32, ProcessArch)>>> =
        Rc::new(RefCell::new(Vec::new()));
    let all_icons: Rc<RefCell<Vec<slint::Image>>> = Rc::new(RefCell::new(Vec::new()));
    let icon_cache: IconCache = Rc::new(RefCell::new(HashMap::new()));
    let settings: Rc<RefCell<Settings>> = Rc::new(RefCell::new(load_settings()));

    refresh_process_list(
        &main_window,
        &all_processes,
        &all_icons,
        &settings,
        &icon_cache,
    );

    main_window.set_close_after_inject(settings.borrow().close_after_inject);
    main_window.set_auto_map_driver(settings.borrow().auto_map_driver);
    main_window.set_hide_system(settings.borrow().hide_system);
    main_window.set_mute_sound(settings.borrow().mute_sound);
    main_window.set_use_manual_map(settings.borrow().use_manual_map);
    audio.set_muted(settings.borrow().mute_sound);

    {
        let detected = faceit_ac_running();
        main_window.set_faceit_active(detected);
        if detected {
            main_window.set_use_manual_map(true);
        }
    }

    {
        let favs = settings.borrow().favorite_dlls.clone();
        refresh_favorites_ui(&main_window, &favs);
    }

    let faceit_timer = Rc::new(slint::Timer::default());
    {
        let ui_handle = main_window.as_weak();
        let settings = settings.clone();
        let t = faceit_timer.clone();
        t.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(5),
            move || {
                if let Some(ui) = ui_handle.upgrade() {
                    let detected = faceit_ac_running();
                    if detected != ui.get_faceit_active() {
                        ui.set_faceit_active(detected);
                        if detected {
                            ui.set_use_manual_map(true);
                            ui.set_status_text("faceit detected, driver option disabled".into());
                            ui.set_status_ok(false);
                        } else {
                            ui.set_use_manual_map(settings.borrow().use_manual_map);
                            ui.set_status_text("".into());
                        }
                    }
                }
            },
        );
    }

    #[cfg(target_os = "windows")]
    {
        let driver_ok = Driver::open(DEVICE_PATH).is_valid();
        main_window.set_driver_ok(driver_ok);

        if settings.borrow().auto_map_driver && !driver_ok {
            let ui_weak = main_window.as_weak();
            std::thread::spawn(move || {
                let result = do_map_driver();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        match result {
                            Ok(msg) => {
                                ui.set_status_text(msg.as_str().into());
                                ui.set_status_ok(true);
                                let ok = Driver::open(DEVICE_PATH).is_valid();
                                ui.set_driver_ok(ok);
                            }
                            Err(e) => {
                                ui.set_status_text(format!("failed: {e}").into());
                                ui.set_status_ok(false);
                            }
                        }
                    }
                });
            });
        }
    }

    {
        let last = load_last_process();
        if !last.is_empty() {
            // remember the name even when it is not running, so the
            // realtime refresh can catch its next pid by itself.
            main_window.set_process_name(last.as_str().into());
            let procs = all_processes.borrow();
            if let Some(idx) = procs
                .iter()
                .position(|(n, _, _)| n.eq_ignore_ascii_case(&last))
            {
                main_window.set_selected_index(idx as i32);
                main_window.set_process_name(procs[idx].0.as_str().into());
                main_window.set_process_pid(procs[idx].1 as i32);
                main_window.set_process_icon(all_icons.borrow()[idx].clone());
                main_window.set_game_status(procs[idx].0.as_str().into());
                main_window.set_game_found(true);
                let dll = main_window.get_dll_path();
                main_window.set_inject_ready(!dll.is_empty());
            } else {
                main_window.set_selected_index(-1);
                main_window.set_game_found(false);
                main_window.set_game_status(format!("{last} (not running)").into());
            }
        }
    }

    let proc_timer = Rc::new(slint::Timer::default());
    {
        let ui_handle = main_window.as_weak();
        let all_processes = all_processes.clone();
        let all_icons = all_icons.clone();
        let settings = settings.clone();
        let icon_cache = icon_cache.clone();
        let t = proc_timer.clone();
        t.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_millis(1000),
            move || {
                if let Some(ui) = ui_handle.upgrade() {
                    refresh_process_list(
                        &ui,
                        &all_processes,
                        &all_icons,
                        &settings,
                        &icon_cache,
                    );
                }
            },
        );
    }

    {
        let recents = load_recent_dlls();
        main_window.set_recent_dlls(
            recents
                .iter()
                .map(|p| p.as_str().into())
                .collect::<Vec<_>>()
                .as_slice()
                .into(),
        );
    }

    {
        let all_processes = all_processes.clone();
        let all_icons = all_icons.clone();
        let settings = settings.clone();
        let ui_handle = main_window.as_weak();
        main_window.on_filter_processes(move |query| {
            let all = all_processes.borrow();
            let icons = all_icons.borrow();
            let s = settings.borrow();
            if let Some(ui) = ui_handle.upgrade() {
                apply_filter(&ui, &all[..], &icons[..], &query.to_string(), &s);
            }
        });
    }

    {
        let all_processes = all_processes.clone();
        let all_icons = all_icons.clone();
        let ui_handle = main_window.as_weak();
        main_window.on_process_selected(move |idx| {
            let all = all_processes.borrow();
            let icons = all_icons.borrow();
            if let Some((name, pid, _arch)) = all.get(idx as usize)
                && let Some(ui) = ui_handle.upgrade()
            {
                let ready = !ui.get_dll_path().is_empty();
                ui.set_process_name(name.as_str().into());
                ui.set_process_pid(*pid as i32);
                ui.set_process_icon(icons.get(idx as usize).cloned().unwrap_or_default());
                ui.set_game_status(name.as_str().into());
                ui.set_game_found(true);
                ui.set_inject_ready(ready);
                save_last_process(name);
            }
        });
    }

    {
        let ui_handle = main_window.as_weak();
        main_window.on_browse_dll(move || {
            if let Some(ui) = ui_handle.upgrade()
                && let Some(path) = rfd::FileDialog::new()
                    .add_filter("DLL Files", &["dll"])
                    .add_filter("All Files", &["*"])
                    .pick_file()
            {
                apply_dll(&ui, &path.to_string_lossy());
            }
        });
    }

    {
        let ui_handle = main_window.as_weak();
        main_window.on_recent_selected(move |path| {
            if let Some(ui) = ui_handle.upgrade() {
                let path = path.to_string();
                if std::path::Path::new(&path).exists() {
                    apply_dll(&ui, &path);
                } else {
                    let recents: Vec<String> = load_recent_dlls()
                        .into_iter()
                        .filter(|p| !p.eq_ignore_ascii_case(&path))
                        .collect();
                    set_config_value("recent_dlls", &recents.join("|"));
                    ui.set_recent_dlls(
                        recents
                            .iter()
                            .map(|p| p.as_str().into())
                            .collect::<Vec<_>>()
                            .as_slice()
                            .into(),
                    );
                }
                ui.set_recents_open(false);
            }
        });
    }

    #[cfg(target_os = "windows")]
    install_drag_drop(&main_window);

    {
        let all_processes = all_processes.clone();
        let all_icons = all_icons.clone();
        let settings = settings.clone();
        let icon_cache = icon_cache.clone();
        let ui_handle = main_window.as_weak();
        main_window.on_refresh_processes(move || {
            if let Some(ui) = ui_handle.upgrade() {
                refresh_process_list(&ui, &all_processes, &all_icons, &settings, &icon_cache);
            }
        });
    }

    {
        let ui_handle = main_window.as_weak();

        let do_inject = std::rc::Rc::new({
            let ui_handle = ui_handle.clone();
            let audio = audio.clone();
            let settings = settings.clone();
            #[cfg(not(target_os = "windows"))]
            let _ = &settings;
            move || {
                let ui = match ui_handle.upgrade() {
                    Some(ui) => ui,
                    None => return,
                };
                let pid = ui.get_process_pid() as u32;
                let dll_path = ui.get_dll_path().to_string();
                let _proc_name = ui.get_process_name().to_string();

                if pid == 0 {
                    audio.play_error();
                    ui.set_status_text("select a process".into());
                    ui.set_status_ok(false);
                    return;
                }
                if dll_path.is_empty() {
                    audio.play_error();
                    ui.set_status_text("select a DLL".into());
                    ui.set_status_ok(false);
                    return;
                }

                ui.set_injecting(true);
                ui.set_status_text("injecting... switch to the game".into());
                ui.set_status_ok(true);

                #[cfg(target_os = "windows")]
                {
                    let ui_weak = ui_handle.clone();
                    let audio = audio.clone();
                    let close_after_inject = settings.borrow().close_after_inject;
                    let use_manual_map = ui.get_use_manual_map();
                    std::thread::spawn(move || {
                        let result = if use_manual_map {
                            // ManualMap toggle ON: classic usermode ManualMap,
                            // reverse-engineered from chudette-injector. No driver needed.
                            meow_core::inject::manual_map_usermode(pid, &dll_path)
                        } else {
                            let driver = Driver::open(DEVICE_PATH);
                            if !driver.is_valid() {
                                audio.play_error();
                                let _ = slint::invoke_from_event_loop(move || {
                                    if let Some(ui) = ui_weak.upgrade() {
                                        ui.set_injecting(false);
                                        ui.set_status_text("driver not available".into());
                                        ui.set_status_ok(false);
                                    }
                                });
                                return;
                            }
                            meow_core::inject::manual_map(&driver, pid, &dll_path)
                        };

                        let audio = audio.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_injecting(false);
                                match result {
                                    Ok(()) => {
                                        audio.play_success();
                                        ui.set_status_text("done! switch to the game".into());
                                        ui.set_status_ok(true);
                                        if close_after_inject {
                                            let _ = slint::quit_event_loop();
                                        }
                                    }
                                    Err(e) => {
                                        audio.play_error();
                                        ui.set_status_text(format!("failed: {e}").into());
                                        ui.set_status_ok(false);
                                    }
                                }
                            }
                        });
                    });
                }
            }
        });

        // shared entry point: disclaimer gate + do_inject.
        // used by the INJECT button and the favorite-dll quick buttons.
        let request_inject = Rc::new({
            let do_inject = do_inject.clone();
            let ui_handle = ui_handle.clone();
            move || {
                if let Some(ui) = ui_handle.upgrade() {
                    if !disclaimer_accepted() {
                        ui.set_disclaimer_open(true);
                        ui.set_disclaimer_inject_pending(true);
                        return;
                    }
                }
                do_inject();
            }
        });

        main_window.on_inject_clicked({
            let request_inject = request_inject.clone();
            move || request_inject()
        });

        {
            let ui_handle = ui_handle.clone();
            let settings = settings.clone();
            let request_inject = request_inject.clone();
            main_window.on_favorite_clicked(move |path| {
                if let Some(ui) = ui_handle.upgrade() {
                    let path = path.to_string();
                    if std::path::Path::new(&path).exists() {
                        apply_dll(&ui, &path);
                        request_inject();
                    } else {
                        let mut s = settings.borrow_mut();
                        s.favorite_dlls.retain(|p| !p.eq_ignore_ascii_case(&path));
                        save_settings(&s);
                        refresh_favorites_ui(&ui, &s.favorite_dlls);
                    }
                }
            });
        }

        {
            let ui_handle = ui_handle.clone();
            let settings = settings.clone();
            main_window.on_toggle_favorite(move || {
                if let Some(ui) = ui_handle.upgrade() {
                    let dll = ui.get_dll_path().to_string();
                    if dll.is_empty() {
                        return;
                    }
                    let mut s = settings.borrow_mut();
                    if let Some(i) = s
                        .favorite_dlls
                        .iter()
                        .position(|p| p.eq_ignore_ascii_case(&dll))
                    {
                        s.favorite_dlls.remove(i);
                    } else {
                        if s.favorite_dlls.len() >= MAX_FAVORITE_DLLS {
                            s.favorite_dlls.remove(0);
                        }
                        s.favorite_dlls.push(dll);
                    }
                    save_settings(&s);
                    refresh_favorites_ui(&ui, &s.favorite_dlls);
                }
            });
        }

        main_window.on_disclaimer_accepted({
            let ui_handle = ui_handle.clone();
            let do_inject = do_inject.clone();
            move || {
                set_disclaimer_accepted();
                if let Some(ui) = ui_handle.upgrade() {
                    ui.set_disclaimer_open(false);
                    if ui.get_disclaimer_inject_pending() {
                        ui.set_disclaimer_inject_pending(false);
                        do_inject();
                    }
                }
            }
        });
    }

    {
        let ui_handle = main_window.as_weak();
        let audio = audio.clone();
        main_window.on_map_driver(move || {
            if let Some(ui) = ui_handle.upgrade() {
                if ui.get_faceit_active() {
                    ui.set_status_text("blocked: faceit ac is running".into());
                    ui.set_status_ok(false);
                    return;
                }
                ui.set_mapping(true);
                ui.set_status_text("mapping driver...".into());
                ui.set_status_ok(true);

                let ui_weak = ui_handle.clone();
                let audio = audio.clone();
                std::thread::spawn(move || {
                    let result = do_map_driver();

                    let audio = audio.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_mapping(false);
                            match result {
                                Ok(msg) => {
                                    // audio.play_success();
                                    ui.set_status_text(msg.as_str().into());
                                    ui.set_status_ok(true);
                                    #[cfg(target_os = "windows")]
                                    {
                                        let driver_ok = Driver::open(DEVICE_PATH).is_valid();
                                        ui.set_driver_ok(driver_ok);
                                    }
                                }
                                Err(e) => {
                                    audio.play_error();
                                    ui.set_status_text(format!("failed: {e}").into());
                                    ui.set_status_ok(false);
                                }
                            }
                        }
                    });
                });
            }
        });
    }

    {
        let settings = settings.clone();
        let all_processes = all_processes.clone();
        let all_icons = all_icons.clone();
        let audio = audio.clone();
        let ui_handle = main_window.as_weak();
        main_window.on_save_settings(move || {
            if let Some(ui) = ui_handle.upgrade() {
                let s = Settings {
                    close_after_inject: ui.get_close_after_inject(),
                    auto_map_driver: ui.get_auto_map_driver(),
                    hide_system: ui.get_hide_system(),
                    mute_sound: ui.get_mute_sound(),
                    use_manual_map: ui.get_use_manual_map(),
                    favorite_dlls: settings.borrow().favorite_dlls.clone(),
                };
                save_settings(&s);
                *settings.borrow_mut() = s.clone();
                audio.set_muted(s.mute_sound);
                let all = all_processes.borrow();
                let icons = all_icons.borrow();
                apply_filter(
                    &ui,
                    &all[..],
                    &icons[..],
                    &ui.get_search_text().to_string(),
                    &s,
                );
            }
        });
    }

    {
        main_window.on_restart_as_admin(move || {
            #[cfg(target_os = "windows")]
            restart_as_admin();
            let _ = slint::quit_event_loop();
        });
        main_window.on_quit_app(move || {
            let _ = slint::quit_event_loop();
        });
    }

    {
        main_window.on_crash_quit(move || {
            let _ = slint::quit_event_loop();
        });
        let ui_handle = main_window.as_weak();
        main_window.on_crash_dismiss(move || {
            if let Some(ui) = ui_handle.upgrade() {
                ui.set_crash_open(false);
            }
        });
    }

    {
        let audio = audio.clone();
        main_window.on_meow_clicked(move || {
            audio.play_meow();
        });
    }

    let grad_timer = std::rc::Rc::new(slint::Timer::default());
    {
        let window_weak = main_window.as_weak();
        let t = grad_timer.clone();
        t.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_millis(16),
            move || {
                let Some(window) = window_weak.upgrade() else {
                    return;
                };
                // the bar is 2x window wide and the gradient repeats exactly
                // at 50%, so one rainbow cycle == window width. wrapping by
                // that amount is seamless (no visible restart).
                let win = window.window();
                let period = win.size().width as f32 / win.scale_factor();
                if period > 0.0 {
                    let mut x = window.get_grad_x();
                    x -= 1.2;
                    while x <= -period {
                        x += period;
                    }
                    window.set_grad_x(x);
                }
            },
        );
    }

    let run_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        main_window.run().unwrap();
    }));
    if let Err(_) = run_result {
        show_crash_window();
    }
    let _ = grad_timer;
    let _ = faceit_timer;
    let _ = proc_timer;
}

#[cfg(target_os = "windows")]
fn install_drag_drop(main_window: &MainWindow) {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    let (_tx, rx) = drop_files::channel();
    let ui_handle = main_window.as_weak();

    let poll_timer = std::rc::Rc::new(slint::Timer::default());
    {
        let ui_handle = ui_handle.clone();
        poll_timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_millis(150),
            move || {
                while let Ok(path) = rx.try_recv() {
                    if path.to_lowercase().ends_with(".dll")
                        && let Some(ui) = ui_handle.upgrade()
                    {
                        apply_dll(&ui, &path);
                    }
                }
            },
        );
    }

    let ui_handle = main_window.as_weak();
    let _ = ui_handle.upgrade_in_event_loop(move |ui| {
        let weak = ui.as_weak();
        let hook_timer = std::rc::Rc::new(slint::Timer::default());
        let cb_timer = hook_timer.clone();
        hook_timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_millis(100),
            move || {
                if let Some(ui) = weak.upgrade()
                    && let Ok(handle) = ui.window().window_handle().window_handle()
                    && let RawWindowHandle::Win32(win32) = handle.as_raw()
                {
                    drop_files::install(win32.hwnd.get());
                    cb_timer.stop();
                }
            },
        );
        std::mem::forget(hook_timer);
    });
    std::mem::forget(poll_timer);
}

#[cfg(target_os = "windows")]
mod drop_files {
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
    use std::sync::mpsc::Sender;
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::UI::Shell::{DragAcceptFiles, DragFinish, DragQueryFileW};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CallWindowProcW, GWLP_WNDPROC, SetWindowLongPtrW, WM_DROPFILES,
    };

    static ORIG_PROC: AtomicIsize = AtomicIsize::new(0);
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    static DROP_SENDER: std::sync::OnceLock<Sender<String>> = std::sync::OnceLock::new();

    pub fn channel() -> (Sender<String>, std::sync::mpsc::Receiver<String>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let _ = DROP_SENDER.set(tx.clone());
        (tx, rx)
    }

    pub fn install(hwnd: isize) {
        if INSTALLED.swap(true, Ordering::SeqCst) {
            return;
        }
        unsafe {
            DragAcceptFiles(hwnd as _, 1);
            let proc = SetWindowLongPtrW(
                hwnd as _,
                GWLP_WNDPROC,
                hook_proc as unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT
                    as usize as isize,
            );
            ORIG_PROC.store(proc, Ordering::SeqCst);
        }
    }

    unsafe extern "system" fn hook_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
        if msg == WM_DROPFILES && w != 0 {
            let hdrop = w as *mut core::ffi::c_void;
            unsafe {
                let count = DragQueryFileW(hdrop, u32::MAX, std::ptr::null_mut(), 0);
                for i in 0..count {
                    let mut buf = [0u16; 520];
                    let len = DragQueryFileW(hdrop, i, buf.as_mut_ptr(), buf.len() as u32);
                    if len > 0
                        && let Some(tx) = DROP_SENDER.get()
                        && let Ok(path) = String::from_utf16(&buf[..len as usize])
                    {
                        let _ = tx.send(path);
                    }
                }
                DragFinish(hdrop);
            }
            return 0;
        }
        let orig = ORIG_PROC.load(Ordering::SeqCst);
        if orig == 0 {
            0
        } else {
            unsafe {
                CallWindowProcW(
                    std::mem::transmute::<
                        isize,
                        Option<unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT>,
                    >(orig),
                    hwnd,
                    msg,
                    w,
                    l,
                )
            }
        }
    }
}
