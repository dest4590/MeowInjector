use rodio::mixer::Mixer;
use rodio::{Decoder, DeviceSinkBuilder, Player};
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

static SUCCESS_SOUNDS: &[&[u8]] = &[
    include_bytes!("../../../assets/success-meow.wav"),
    include_bytes!("../../../assets/success2-meow.wav"),
    include_bytes!("../../../assets/success3-meow.wav"),
];
static ERROR_SOUNDS: &[&[u8]] = &[
    include_bytes!("../../../assets/error-meow.wav"),
    include_bytes!("../../../assets/error2-meow.wav"),
    include_bytes!("../../../assets/error3-meow.wav"),
];

#[derive(Clone)]
pub struct Audio {
    mixer: Mixer,
    _sink_keepalive: Arc<()>,
    muted: Arc<AtomicBool>,
}

impl Audio {
    pub fn new() -> Self {
        match DeviceSinkBuilder::open_default_sink() {
            Ok(mut sink) => {
                sink.log_on_drop(false);
                let mixer = sink.mixer().clone();
                Box::leak(Box::new(sink));
                Self {
                    mixer,
                    muted: Arc::new(AtomicBool::new(false)),
                    _sink_keepalive: Arc::new(()),
                }
            }
            Err(e) => {
                log::warn!("Failed to open audio device: {e}");
                let (mixer, _source) = rodio::mixer::mixer(
                    std::num::NonZeroU16::new(1).unwrap(),
                    std::num::NonZeroU32::new(44_100).unwrap(),
                );
                Self {
                    mixer,
                    muted: Arc::new(AtomicBool::new(false)),
                    _sink_keepalive: Arc::new(()),
                }
            }
        }
    }

    pub fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::SeqCst);
    }

    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub fn play_success(&self) {
        if self.muted.load(Ordering::SeqCst) {
            return;
        }
        let idx = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos() as usize)
            % SUCCESS_SOUNDS.len();
        self.play_raw(SUCCESS_SOUNDS[idx]);
    }

    pub fn play_error(&self) {
        if self.muted.load(Ordering::SeqCst) {
            return;
        }
        let idx = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos() as usize)
            % ERROR_SOUNDS.len();
        self.play_raw(ERROR_SOUNDS[idx]);
    }

    pub fn play_meow(&self) {
        self.play_success();
    }

    fn play_raw(&self, data: &[u8]) {
        let cursor = Cursor::new(data.to_vec());
        match Decoder::try_from(cursor) {
            Ok(decoder) => {
                let player = Player::connect_new(&self.mixer);
                player.append(decoder);
                std::thread::spawn(move || {
                    player.sleep_until_end();
                });
            }
            Err(e) => {
                log::warn!("Failed to decode sound: {e}");
            }
        }
    }
}
