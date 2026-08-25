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

fn save_last_process(name: &str) {
    let _ = std::fs::write(config_path(), format!("last_process={}", name));
}

fn load_last_process() -> String {
    std::fs::read_to_string(config_path())
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("last_process="))
                .map(|l| l.trim_start_matches("last_process=").to_string())
        })
        .unwrap_or_default()
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
        let driver = Driver::open(DEVICE_PATH);
        main_window.set_driver_ok(driver.is_valid());
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
                let path_str = path.to_string_lossy().to_string();
                ui.set_dll_path(path_str.clone().into());

                let short_name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| path_str);
                ui.set_dll_hint(format!("{}...", short_name).into());
                ui.set_status_text("".into());

                let ready = ui.get_process_pid() > 0;
                ui.set_inject_ready(ready);
            }
        });
    }

    {
        let all_processes = all_processes.clone();
        let all_icons = all_icons.clone();
        let ui_handle = main_window.as_weak();
        main_window.on_refresh_processes(move || {
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
                ui.set_filtered_names(slint::ModelRc::from(names.as_slice()));
                ui.set_filtered_pids(slint::ModelRc::from(pids.as_slice()));
                ui.set_filtered_indices(slint::ModelRc::from(indices.as_slice()));
                ui.set_filtered_icons(slint::ModelRc::from(icons.as_slice()));
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
                                        let driver = Driver::open(DEVICE_PATH);
                                        ui.set_driver_ok(driver.is_valid());
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

    main_window.run().unwrap();
}
