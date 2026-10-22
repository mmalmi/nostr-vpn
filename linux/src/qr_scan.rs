use std::cell::RefCell;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use adw::prelude::*;
use gtk::glib;

pub fn decode_from_path(path: &Path) -> Result<String, String> {
    let image = image::open(path).map_err(|error| format!("Could not read image: {error}"))?;
    let luma = image.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(luma);

    for grid in prepared.detect_grids() {
        if let Ok((_meta, content)) = grid.decode() {
            let content = content.trim().to_string();
            if !content.is_empty() {
                return Ok(content);
            }
        }
    }

    Err("No QR code found".to_string())
}

// Linux videodev2.h: v4l2_capability, filled by VIDIOC_QUERYCAP.
#[repr(C)]
#[derive(Default)]
struct VideoCapabilities {
    driver: [u8; 16],
    card: [u8; 32],
    bus_info: [u8; 32],
    version: u32,
    capabilities: u32,
    device_caps: u32,
    reserved: [u32; 3],
}

impl VideoCapabilities {
    fn can_capture(&self) -> bool {
        const VIDEO_CAPTURE: u32 = 0x0000_0001;
        const READWRITE: u32 = 0x0100_0000;
        const STREAMING: u32 = 0x0400_0000;
        const DEVICE_CAPS: u32 = 0x8000_0000;
        let capabilities = if self.capabilities & DEVICE_CAPS != 0 {
            self.device_caps
        } else {
            self.capabilities
        };
        capabilities & VIDEO_CAPTURE != 0 && capabilities & (READWRITE | STREAMING) != 0
    }
}

nix::ioctl_read!(query_video_capabilities, b'V', 0, VideoCapabilities);

fn capture_device_name(path: &Path) -> Option<String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let mut capabilities = VideoCapabilities::default();
    // SAFETY: The open descriptor stays valid, and the writable repr(C) buffer
    // matches the kernel's v4l2_capability layout and the ioctl's encoded size.
    unsafe { query_video_capabilities(file.as_raw_fd(), &mut capabilities) }.ok()?;
    if !capabilities.can_capture() {
        return None;
    }
    let name = capabilities.card.split(|byte| *byte == 0).next()?;
    Some(String::from_utf8_lossy(name).into_owned())
}

fn camera_devices() -> Vec<(PathBuf, String)> {
    let mut devices = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            let Some(index) = file_name
                .strip_prefix("video")
                .and_then(|index| index.parse::<u32>().ok())
            else {
                continue;
            };
            let path = entry.path();
            let Some(name) = capture_device_name(&path) else {
                continue;
            };
            let label = format!("{} ({})", name.trim(), path.display());
            devices.push((index, path, label));
        }
    }
    devices.sort_by_key(|(index, _, _)| *index);
    devices
        .into_iter()
        .map(|(_, path, label)| (path, label))
        .collect()
}

pub fn open_scanner<F, E>(parent: Option<&gtk::Window>, on_result: F, on_error: E)
where
    F: Fn(String) + 'static,
    E: Fn(String) + 'static,
{
    let devices = camera_devices();
    if !command_available("zbarcam") || devices.is_empty() {
        pick_and_decode(parent, on_result, on_error);
        return;
    }

    let dialog = adw::Dialog::builder()
        .title("Scan QR")
        .content_width(360)
        .build();

    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.set_margin_top(20);
    content.set_margin_bottom(20);
    content.set_margin_start(20);
    content.set_margin_end(20);

    let scanner_icon = gtk::Image::from_icon_name("camera-photo-symbolic");
    scanner_icon.set_pixel_size(56);
    scanner_icon.add_css_class("dim-label");
    content.append(&scanner_icon);

    let camera_label = gtk::Label::new(Some("Camera"));
    camera_label.set_xalign(0.0);
    content.append(&camera_label);
    let labels: Vec<&str> = devices.iter().map(|(_, label)| label.as_str()).collect();
    let camera = gtk::DropDown::from_strings(&labels);
    camera_label.set_mnemonic_widget(Some(&camera));
    content.append(&camera);

    let status = gtk::Label::new(Some("Scanning"));
    status.add_css_class("dim-label");
    status.set_halign(gtk::Align::Center);
    status.set_wrap(true);
    content.append(&status);

    let pick_image = gtk::Button::with_label("Image");
    pick_image.add_css_class("flat");
    content.append(&pick_image);

    dialog.set_child(Some(&content));

    let capture = Rc::new(RefCell::new(None::<CameraCapture>));
    let on_result = Rc::new(on_result);
    let on_error = Rc::new(on_error);

    {
        let capture = capture.clone();
        let on_result = on_result.clone();
        let dialog = dialog.downgrade();
        let start_scan = move |camera: &gtk::DropDown| {
            capture.borrow_mut().take();
            let Some((device, _)) = devices.get(camera.selected() as usize) else {
                return;
            };
            status.set_label("Scanning");
            let (scan, event_rx) = CameraCapture::start(device.clone());
            let stop = scan.stop.clone();
            *capture.borrow_mut() = Some(scan);
            let on_result = on_result.clone();
            let dialog = dialog.clone();
            let status = status.clone();
            glib::timeout_add_local(Duration::from_millis(150), move || {
                if stop.load(Ordering::SeqCst) {
                    return glib::ControlFlow::Break;
                }
                if let Ok(event) = event_rx.try_recv() {
                    match event {
                        CameraEvent::Found(text) => {
                            (on_result)(text);
                            if let Some(dialog) = dialog.upgrade() {
                                dialog.close();
                            }
                        }
                        CameraEvent::Error(error) => {
                            status.set_label(&format!(
                                "{error} Choose another camera or import an image."
                            ));
                        }
                    }
                    return glib::ControlFlow::Break;
                }
                glib::ControlFlow::Continue
            });
        };
        start_scan(&camera);
        camera.connect_selected_notify(start_scan);
    }

    {
        let on_result = on_result.clone();
        let on_error = on_error.clone();
        let dialog = dialog.clone();
        let parent = parent.cloned();
        pick_image.connect_clicked(move |_| {
            let on_result = on_result.clone();
            let dialog = dialog.clone();
            pick_and_decode(
                parent.as_ref(),
                move |text| {
                    (on_result)(text);
                    dialog.close();
                },
                {
                    let on_error = on_error.clone();
                    move |error| (on_error)(error)
                },
            );
        });
    }

    {
        dialog.connect_closed(move |_| {
            capture.borrow_mut().take();
        });
    }

    dialog.present(parent);
}

fn pick_and_decode<F, E>(parent: Option<&gtk::Window>, on_result: F, on_error: E)
where
    F: Fn(String) + 'static,
    E: Fn(String) + 'static,
{
    let dialog = gtk::FileDialog::builder()
        .title("Import QR image")
        .accept_label("Import")
        .build();
    dialog.open(parent, gtk::gio::Cancellable::NONE, move |result| {
        let Ok(file) = result else {
            return;
        };
        let Some(path) = file.path() else {
            on_error("Could not open image".to_string());
            return;
        };
        match decode_from_path(&path) {
            Ok(text) => on_result(text),
            Err(error) => on_error(error),
        }
    });
}

enum CameraEvent {
    Found(String),
    Error(String),
}

struct CameraCapture {
    stop: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
}

impl CameraCapture {
    fn start(device: PathBuf) -> (Self, mpsc::Receiver<CameraEvent>) {
        let capture = Self {
            stop: Arc::new(AtomicBool::new(false)),
            child: Arc::new(Mutex::new(None)),
        };
        let (event_tx, event_rx) = mpsc::channel();
        let stop = capture.stop.clone();
        let child = capture.child.clone();
        thread::spawn(move || capture_loop(device, stop, child, event_tx));
        (capture, event_rx)
    }
}

impl Drop for CameraCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        kill_child(&self.child);
    }
}

fn capture_loop(
    device: PathBuf,
    stop: Arc<AtomicBool>,
    child_slot: Arc<Mutex<Option<Child>>>,
    event_tx: Sender<CameraEvent>,
) {
    let mut slot = child_slot.lock().expect("camera child lock");
    if stop.load(Ordering::SeqCst) {
        return;
    }
    let mut child = match Command::new("zbarcam")
        .args(["--raw", "--quiet"])
        .arg(&device)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            let _ = event_tx.send(CameraEvent::Error(format!(
                "Camera scanner unavailable: {error}"
            )));
            return;
        }
    };
    let stdout = child.stdout.take();
    *slot = Some(child);
    drop(slot);

    let Some(stdout) = stdout else {
        kill_child(&child_slot);
        let _ = event_tx.send(CameraEvent::Error("Camera stream unavailable".to_string()));
        return;
    };

    let mut reader = std::io::BufReader::new(stdout);
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let mut line = String::new();
        match std::io::BufRead::read_line(&mut reader, &mut line) {
            Ok(0) => {
                let _ = event_tx.send(CameraEvent::Error(format!(
                    "Camera scan stopped for {}.",
                    device.display()
                )));
                break;
            }
            Ok(_) => {
                let text = line.trim().to_string();
                if !text.is_empty() {
                    let _ = event_tx.send(CameraEvent::Found(text));
                    break;
                }
            }
            Err(error) => {
                let _ = event_tx.send(CameraEvent::Error(format!("Camera scan failed: {error}")));
                break;
            }
        }
    }
    kill_child(&child_slot);
}

fn kill_child(child_slot: &Arc<Mutex<Option<Child>>>) {
    if let Ok(mut slot) = child_slot.lock() {
        if let Some(mut child) = slot.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn command_available(name: &str) -> bool {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .any(|path| path.join(name).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{GrayImage, Luma};
    use qrcode::QrCode;

    #[test]
    fn camera_capabilities_exclude_metadata_and_output_nodes() {
        // Raw videodev2.h capability bits, including the aggregate capabilities
        // shared by a webcam's video and metadata nodes.
        for (capabilities, device_caps, expected) in [
            (0x8480_0001, 0x0400_0001, true),
            (0x8480_0001, 0x0480_0000, false),
            (0x8480_0001, 0, false),
            (0x0400_0001, 0, true),
            (0x0100_0001, 0, true),
            (0x0480_0000, 0, false),
            (0x0400_0002, 0, false),
            (0x0000_0001, 0, false),
        ] {
            let node = VideoCapabilities {
                capabilities,
                device_caps,
                ..VideoCapabilities::default()
            };
            assert_eq!(
                node.can_capture(),
                expected,
                "wrong capture decision for capabilities={capabilities:#x}, device_caps={device_caps:#x}"
            );
        }
        assert_eq!(std::mem::size_of::<VideoCapabilities>(), 104);
        assert!(capture_device_name(Path::new("/dev/null")).is_none());
    }

    #[test]
    fn camera_process_lifecycle() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        // Isolate PATH in a subprocess so other tests can run in parallel.
        if std::env::var_os("NVPN_CAMERA_PROCESS_TEST").is_none() {
            let directory =
                std::env::temp_dir().join(format!("nvpn-camera-test-{}", std::process::id()));
            std::fs::create_dir_all(&directory).unwrap();
            let scanner = directory.join("zbarcam");
            std::fs::write(
                &scanner,
                "#!/bin/sh\ncase \"$3\" in\n/dev/video4) printf '%s\\n' \"$3\" ;;\n/dev/video6) exit 1 ;;\n*) exec /bin/sleep 30 ;;\nesac\n",
            )
            .unwrap();
            std::fs::set_permissions(&scanner, std::fs::Permissions::from_mode(0o700)).unwrap();
            let result = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "qr_scan::tests::camera_process_lifecycle",
                    "--nocapture",
                ])
                .env("NVPN_CAMERA_PROCESS_TEST", "1")
                .env("PATH", &directory)
                .status();
            std::fs::remove_dir_all(directory).unwrap();
            assert!(result.unwrap().success());
            return;
        }

        let timeout = Duration::from_secs(5);
        let (capture, events) = CameraCapture::start(PathBuf::from("/dev/video4"));
        assert!(matches!(
            events.recv_timeout(timeout).unwrap(),
            CameraEvent::Found(text) if text == "/dev/video4"
        ));
        drop(capture);

        let (capture, events) = CameraCapture::start(PathBuf::from("/dev/video6"));
        assert!(matches!(
            events.recv_timeout(timeout).unwrap(),
            CameraEvent::Error(error) if error.contains("/dev/video6")
        ));
        drop(capture);

        let (capture, events) = CameraCapture::start(PathBuf::from("/dev/video8"));
        let deadline = Instant::now() + timeout;
        let pid = loop {
            if let Some(child) = capture.child.lock().unwrap().as_ref() {
                break child.id();
            }
            assert!(Instant::now() < deadline, "camera process did not start");
            thread::sleep(Duration::from_millis(10));
        };
        drop(capture);
        assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
        // EOF after cancellation is harmless, but the worker must exit.
        while events.recv_timeout(timeout).is_ok() {}
        assert!(matches!(
            events.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));

        for _ in 0..20 {
            let (capture, events) = CameraCapture::start(PathBuf::from("/dev/video8"));
            drop(capture);
            while events.recv_timeout(timeout).is_ok() {}
            assert!(matches!(
                events.try_recv(),
                Err(mpsc::TryRecvError::Disconnected)
            ));
        }
    }

    #[test]
    fn decodes_qr_png() {
        let text = "nvpn://join-request/test";
        let code = QrCode::new(text.as_bytes()).expect("build qr");
        let modules = code.width();
        let quiet = 4usize;
        let scale = 8usize;
        let size = (modules + quiet * 2) * scale;
        let colors = code.to_colors();
        let image = GrayImage::from_fn(size as u32, size as u32, |x, y| {
            let module_x = x as usize / scale;
            let module_y = y as usize / scale;
            if module_x < quiet
                || module_y < quiet
                || module_x >= modules + quiet
                || module_y >= modules + quiet
            {
                return Luma([255]);
            }
            let index = (module_y - quiet) * modules + (module_x - quiet);
            if matches!(colors[index], qrcode::Color::Dark) {
                Luma([0])
            } else {
                Luma([255])
            }
        });
        let path = std::env::temp_dir().join(format!("nostr-vpn-qr-{}.png", std::process::id()));
        image.save(&path).expect("write qr png");

        let decoded = decode_from_path(&path).expect("decode qr png");
        let _ = std::fs::remove_file(&path);

        assert_eq!(decoded, text);
    }
}
