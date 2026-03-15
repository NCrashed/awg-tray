use crate::vpn::VpnStatus;

const SIZE: i32 = 22;

/// Generate a tray icon for the given VPN status.
/// Returns a ksni::Icon with ARGB32 pixel data.
pub fn status_icon(status: &VpnStatus) -> ksni::Icon {
    let (r, g, b) = match status {
        VpnStatus::Connected(_) => (0x2eu8, 0xcc, 0x71),  // green
        VpnStatus::Disconnected => (0xe7, 0x4c, 0x3c),    // red
        VpnStatus::Connecting(_) => (0xf3, 0x9c, 0x12),   // amber
    };

    let mut data = Vec::with_capacity((SIZE * SIZE * 4) as usize);

    let center = SIZE as f32 / 2.0;
    let radius = center - 1.0;

    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 - center + 0.5;
            let dy = y as f32 - center + 0.5;
            let dist = (dx * dx + dy * dy).sqrt();

            if dist <= radius {
                // Slight edge smoothing
                let alpha = if dist > radius - 1.0 {
                    ((radius - dist) * 255.0) as u8
                } else {
                    255
                };
                data.extend_from_slice(&[alpha, r, g, b]);
            } else {
                data.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }

    ksni::Icon {
        width: SIZE,
        height: SIZE,
        data,
    }
}
