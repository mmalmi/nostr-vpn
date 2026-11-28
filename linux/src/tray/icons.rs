use std::sync::OnceLock;

use glib::variant::ToVariant;
use image::{Rgba, RgbaImage};
use nostr_vpn_app_core::NativeAppState;

/// Same states and colors as macOS `InternetExitIndicator`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Indicator {
    Hidden,
    Connecting,
    Connected,
    Attention,
}

impl Indicator {
    fn color(self) -> Option<Rgba<u8>> {
        match self {
            Self::Hidden => None,
            Self::Connecting => Some(Rgba([255, 149, 0, 255])),
            Self::Connected => Some(Rgba([52, 199, 89, 255])),
            Self::Attention => Some(Rgba([255, 59, 48, 255])),
        }
    }
}

pub(super) fn internet_indicator(state: &NativeAppState) -> Indicator {
    if !state.vpn_enabled || state.internet_source == "direct" {
        Indicator::Hidden
    } else if state.exit_node_needs_attention || state.exit_node_blocked {
        Indicator::Attention
    } else if state.exit_node_active {
        Indicator::Connected
    } else {
        Indicator::Connecting
    }
}

pub(super) fn selling_indicator(state: &NativeAppState) -> Indicator {
    match (state.paid_exit_seller.enabled, state.paid_exit_seller.ready) {
        (false, _) => Indicator::Hidden,
        (true, true) => Indicator::Connected,
        (true, false) => Indicator::Connecting,
    }
}

pub(super) fn tray_indicator(state: &NativeAppState) -> Indicator {
    let connection = internet_indicator(state);
    let selling = selling_indicator(state);
    if connection == Indicator::Attention {
        Indicator::Attention
    } else if connection == Indicator::Connecting
        || selling == Indicator::Connecting
        || (state.vpn_enabled && !state.vpn_active)
    {
        Indicator::Connecting
    } else if connection == Indicator::Connected
        || selling == Indicator::Connected
        || (state.vpn_enabled && state.vpn_active)
    {
        Indicator::Connected
    } else {
        Indicator::Hidden
    }
}

/// Keeps the icon visible in hosts that hide passive items (Waybar does by
/// default), as on macOS and Windows.
pub(super) fn sni_status(indicator: Indicator) -> &'static str {
    if indicator == Indicator::Attention {
        "NeedsAttention"
    } else {
        "Active"
    }
}

pub(super) fn empty_pixmaps() -> glib::Variant {
    glib::Variant::array_from_iter_with_type(
        glib::VariantTy::new("(iiay)").expect("icon pixmap type"),
        std::iter::empty::<glib::Variant>(),
    )
}

pub(super) fn tray_icon(indicator: Indicator) -> glib::Variant {
    let icon_type = glib::VariantTy::new("(iiay)").expect("icon pixmap type");
    glib::Variant::array_from_iter_with_type(
        icon_type,
        [
            include_bytes!("../../resources/nostr-vpn-tray-24.png").as_slice(),
            include_bytes!("../../resources/nostr-vpn-tray-48.png").as_slice(),
        ]
        .into_iter()
        .map(|bytes| tray_icon_pixmap(bytes, indicator)),
    )
}

fn tray_icon_pixmap(bytes: &[u8], indicator: Indicator) -> glib::Variant {
    let mut image = image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
        .expect("bundled tray icon is a valid PNG")
        .into_rgba8();
    if let Some(color) = indicator.color() {
        // The status dot replaces the N's bottom-right node with a transparent ring.
        let size = image.width().min(image.height()) as f32;
        paint_dot(
            &mut image,
            (size * 0.794, size * 0.817),
            size * 0.15,
            size * 0.05,
            color,
        );
    }
    let (width, height) = image.dimensions();
    // StatusNotifierItem pixmaps are ARGB32 in network byte order.
    let mut data = image.into_vec();
    for pixel in data.chunks_exact_mut(4) {
        pixel.rotate_right(1);
    }
    glib::Variant::tuple_from_iter([
        (width as i32).to_variant(),
        (height as i32).to_variant(),
        data.to_variant(),
    ])
}

/// Antialiased dot at `center`, clearing `gap` pixels around it.
fn paint_dot(image: &mut RgbaImage, center: (f32, f32), radius: f32, gap: f32, color: Rgba<u8>) {
    for y in 0..image.height() {
        for x in 0..image.width() {
            let dx = x as f32 + 0.5 - center.0;
            let dy = y as f32 + 0.5 - center.1;
            let distance = (dx * dx + dy * dy).sqrt();
            let pixel = image.get_pixel_mut(x, y);
            let keep = (distance - radius - gap + 0.5).clamp(0.0, 1.0);
            pixel[3] = (f32::from(pixel[3]) * keep).round() as u8;
            let fill = (radius + 0.5 - distance).clamp(0.0, 1.0);
            if fill > 0.0 {
                let alpha = f32::from(pixel[3]) / 255.0;
                let out = fill + alpha * (1.0 - fill);
                for channel in 0..3 {
                    pixel[channel] = ((f32::from(color[channel]) * fill
                        + f32::from(pixel[channel]) * alpha * (1.0 - fill))
                        / out)
                        .round() as u8;
                }
                pixel[3] = (out * 255.0).round() as u8;
            }
        }
    }
}

/// Small colored dot for menu items, cached once per indicator state.
pub(super) fn dot_png(indicator: Indicator) -> Option<&'static [u8]> {
    static CACHE: [OnceLock<Vec<u8>>; 3] = [OnceLock::new(), OnceLock::new(), OnceLock::new()];
    let index = match indicator {
        Indicator::Hidden => return None,
        Indicator::Connecting => 0,
        Indicator::Connected => 1,
        Indicator::Attention => 2,
    };
    let bytes = CACHE[index].get_or_init(|| {
        let mut image = RgbaImage::new(12, 12);
        paint_dot(
            &mut image,
            (6.0, 6.0),
            4.0,
            0.0,
            indicator.color().expect("dot color"),
        );
        let mut out = Vec::new();
        let _ = image.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png);
        out
    });
    (!bytes.is_empty()).then_some(bytes.as_slice())
}
