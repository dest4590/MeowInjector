slint::include_modules!();

mod sound;

#[cfg(target_os = "windows")]
use meow_core::driver::Driver;
use meow_core::process::{extract_process_icon, list_processes};
use std::cell::RefCell;
use std::rc::Rc;

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
}

pub fn run_gui() {
    let main_window = MainWindow::new().unwrap();
    let audio = sound::Audio::new();

    let all_processes: Rc<RefCell<Vec<(String, u32)>>> = Rc::new(RefCell::new(Vec::new()));
    let all_icons: Rc<RefCell<Vec<slint::Image>>> = Rc::new(RefCell::new(Vec::new()));

    {
        let procs = list_processes();
        let names: Vec<slint::SharedString> =
            procs.iter().map(|(n, _)| n.as_str().into()).collect();
        let pids: Vec<i32> = procs.iter().map(|(_, p)| *p as i32).collect();
        let indices: Vec<i32> = (0..procs.len() as i32).collect();
        let icons: Vec<slint::Image> = procs
            .iter()
            .map(|(_, pid)| {
                extract_process_icon(*pid)
                    .map(|(rgba, w, h)| {
                        let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                            &rgba, w, h,
                        );
                        slint::Image::from_rgba8(buf)
                    })
                    .unwrap_or_default()
            })
            .collect();

        main_window.set_process_names(slint::ModelRc::from(names.as_slice()));
        main_window.set_process_pids(slint::ModelRc::from(pids.as_slice()));
        main_window.set_filtered_names(slint::ModelRc::from(names.as_slice()));
        main_window.set_filtered_pids(slint::ModelRc::from(pids.as_slice()));
        main_window.set_filtered_indices(slint::ModelRc::from(indices.as_slice()));
        main_window.set_filtered_icons(slint::ModelRc::from(icons.as_slice()));
        *all_processes.borrow_mut() = procs;
        *all_icons.borrow_mut() = icons;
    }

    #[cfg(target_os = "windows")]
    {
        let driver_ok = Driver::open(DEVICE_PATH)
            .map(|d| d.is_valid())
            .unwrap_or(false);
        main_window.set_driver_ok(driver_ok);
    }

    {
        let last = load_last_process();
        if !last.is_empty() {
            let procs = all_processes.borrow();
            if let Some(idx) = procs
                .iter()
                .position(|(n, _)| n.eq_ignore_ascii_case(&last))
            {
                main_window.set_selected_index(idx as i32);
                main_window.set_process_name(procs[idx].0.as_str().into());
                main_window.set_process_pid(procs[idx].1 as i32);
                main_window.set_game_status(procs[idx].0.as_str().into());
                main_window.set_game_found(true);
                let dll = main_window.get_dll_path();
                main_window.set_inject_ready(!dll.is_empty());
            }
        }
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
        let ui_handle = main_window.as_weak();
        main_window.on_filter_processes(move |query| {
            let all = all_processes.borrow();
            let icons = all_icons.borrow();
            let q = query.to_string().to_lowercase();

            let mut filtered_names: Vec<slint::SharedString> = Vec::new();
            let mut filtered_pids: Vec<i32> = Vec::new();
            let mut filtered_indices: Vec<i32> = Vec::new();
            let mut filtered_icons: Vec<slint::Image> = Vec::new();

            for (i, (name, pid)) in all.iter().enumerate() {
                if q.is_empty() || name.to_lowercase().contains(&q) {
                    filtered_names.push(name.as_str().into());
                    filtered_pids.push(*pid as i32);
                    filtered_indices.push(i as i32);
                    filtered_icons.push(icons.get(i).cloned().unwrap_or_default());
                }
            }

            if let Some(ui) = ui_handle.upgrade() {
                ui.set_filtered_names(slint::ModelRc::from(filtered_names.as_slice()));
                ui.set_filtered_pids(slint::ModelRc::from(filtered_pids.as_slice()));
                ui.set_filtered_indices(slint::ModelRc::from(filtered_indices.as_slice()));
                ui.set_filtered_icons(slint::ModelRc::from(filtered_icons.as_slice()));
            }
        });
    }

    {
        let all_processes = all_processes.clone();
        let ui_handle = main_window.as_weak();
        main_window.on_process_selected(move |idx| {
            let all = all_processes.borrow();
            if let Some((name, pid)) = all.get(idx as usize)
                && let Some(ui) = ui_handle.upgrade()
            {
                let ready = !ui.get_dll_path().is_empty();
                ui.set_process_name(name.as_str().into());
                ui.set_process_pid(*pid as i32);
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
        let ui_handle = main_window.as_weak();
        main_window.on_refresh_processes(move || {
            let procs = list_processes();
            let names: Vec<slint::SharedString> =
                procs.iter().map(|(n, _)| n.as_str().into()).collect();
            let pids: Vec<i32> = procs.iter().map(|(_, p)| *p as i32).collect();
            let icons: Vec<slint::Image> = procs
                .iter()
                .map(|(_, pid)| {
                    extract_process_icon(*pid)
                        .map(|(rgba, w, h)| {
                            let buf =
                                slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                                    &rgba, w, h,
                                );
                            slint::Image::from_rgba8(buf)
                        })
                        .unwrap_or_default()
                })
                .collect();

            *all_processes.borrow_mut() = procs;
            *all_icons.borrow_mut() = icons.clone();

            if let Some(ui) = ui_handle.upgrade() {
                ui.set_process_names(slint::ModelRc::from(names.as_slice()));
                ui.set_process_pids(slint::ModelRc::from(pids.as_slice()));

                let query = ui.get_search_text().to_string().to_lowercase();
                let all = all_processes.borrow();
                let ic = all_icons.borrow();

                let mut fn_: Vec<slint::SharedString> = Vec::new();
                let mut fp_: Vec<i32> = Vec::new();
                let mut fi_: Vec<i32> = Vec::new();
                let mut fic_: Vec<slint::Image> = Vec::new();

                for (i, (name, pid)) in all.iter().enumerate() {
                    if query.is_empty() || name.to_lowercase().contains(&query) {
                        fn_.push(name.as_str().into());
                        fp_.push(*pid as i32);
                        fi_.push(i as i32);
                        fic_.push(ic.get(i).cloned().unwrap_or_default());
                    }
                }

                ui.set_filtered_names(slint::ModelRc::from(fn_.as_slice()));
                ui.set_filtered_pids(slint::ModelRc::from(fp_.as_slice()));
                ui.set_filtered_indices(slint::ModelRc::from(fi_.as_slice()));
                ui.set_filtered_icons(slint::ModelRc::from(fic_.as_slice()));
            }
        });
    }

    {
        let ui_handle = main_window.as_weak();
        let audio = audio.clone();
        main_window.on_inject_clicked(move || {
            if let Some(ui) = ui_handle.upgrade() {
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
                    std::thread::spawn(move || {
                        let driver = match Driver::open(DEVICE_PATH) {
                            Ok(d) if d.is_valid() => d,
                            _ => {
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
                        };
                        let result = meow_core::inject::manual_map(&driver, pid, &dll_path);

                        let audio = audio.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_injecting(false);
                                match result {
                                    Ok(()) => {
                                        audio.play_success();
                                        ui.set_status_text("done! switch to the game".into());
                                        ui.set_status_ok(true);
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
    }

    {
        let ui_handle = main_window.as_weak();
        let audio = audio.clone();
        main_window.on_map_driver(move || {
            if let Some(ui) = ui_handle.upgrade() {
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
                                    audio.play_success();
                                    ui.set_status_text(msg.as_str().into());
                                    ui.set_status_ok(true);
                                    #[cfg(target_os = "windows")]
                                    {
                                        let driver_ok = Driver::open(DEVICE_PATH)
                                            .map(|d| d.is_valid())
                                            .unwrap_or(false);
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
                let mut x = window.get_grad_x();
                x -= 360.0 * 0.003;
                if x <= -360.0 {
                    x += 360.0;
                }
                window.set_grad_x(x);
            },
        );
    }

    main_window.run().unwrap();
    let _ = grad_timer;
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
