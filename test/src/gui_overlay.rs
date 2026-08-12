use crate::game_engine::{CyberDefenderGame, GAME_HEIGHT, GAME_WIDTH};
use crate::win32_ffi::*;
use std::hint::black_box;

fn draw_rect(hdc: HDC, left: i32, top: i32, right: i32, bottom: i32, color: DWORD) {
    unsafe {
        let brush = CreateSolidBrush(color);
        let rc = RECT { left, top, right, bottom };
        FillRect(hdc, &rc, brush);
        DeleteObject(brush);
    }
}

fn draw_text(hdc: HDC, x: i32, y: i32, text: &str, color: DWORD) {
    unsafe {
        SetTextColor(hdc, color);
        SetBkMode(hdc, TRANSPARENT);
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        TextOutW(hdc, x, y, wide.as_ptr(), (wide.len() - 1) as i32);
    }
}

#[inline(never)]
pub fn render_game_and_telemetry_hud(
    hdc: HDC,
    game: &CyberDefenderGame,
    stage_results: &[(&'static str, u64); 15],
    final_checksum: u64,
) {
    // 1. Fill Dark Background (RGB: 10, 15, 25)
    draw_rect(hdc, 0, 0, GAME_WIDTH, GAME_HEIGHT, rgb(10, 15, 25));

    // 2. Render Matrix Rain Drops
    for drop in &game.drops {
        let green_intensity = ((drop.speed * 40).clamp(100, 255)) as u8;
        let color = rgb(0, green_intensity, 50);
        let glyph_str = format!("{}", (drop.glyph as u8) as char);
        draw_text(hdc, drop.x, drop.y, &glyph_str, color);
    }

    // 3. Render Data Cubes
    for cube in &game.cubes {
        if cube.y > 0 && cube.y < 580 {
            let cx = cube.x;
            let cy = cube.y;
            let color = if cube.is_secure {
                rgb(0, 220, 180) // Cyan/Green for Secure
            } else {
                rgb(240, 50, 60) // Red for Corrupted
            };
            draw_rect(hdc, cx - 12, cy - 12, cx + 12, cy + 12, color);
            draw_text(
                hdc,
                cx - 10,
                cy - 8,
                if cube.is_secure { "SEC" } else { "ERR" },
                rgb(255, 255, 255),
            );
        }
    }

    // 4. Render Player Cyber Drone & Shield
    let px = game.player_x;
    let py = game.player_y;
    // Shield aura
    draw_rect(hdc, px - 25, py - 18, px + 25, py + 18, rgb(0, 150, 255));
    // Core ship
    draw_rect(hdc, px - 15, py - 10, px + 15, py + 10, rgb(255, 255, 255));
    draw_text(hdc, px - 12, py - 7, "BTG", rgb(0, 50, 150));

    // 5. Draw Header HUD Panel
    draw_rect(hdc, 0, 0, GAME_WIDTH, 80, rgb(20, 30, 45));
    draw_rect(hdc, 0, 78, GAME_WIDTH, 80, rgb(0, 255, 180));

    draw_text(
        hdc,
        15,
        10,
        "BTG Cyber Defender & Protection Telemetry HUD v3.0",
        rgb(0, 255, 200),
    );
    draw_text(
        hdc,
        15,
        32,
        &format!("SCORE: {:08}   HEALTH: {}%   COMBO: {}x", game.score, game.health, game.combo),
        rgb(255, 255, 255),
    );
    draw_text(
        hdc,
        15,
        52,
        &format!("FINAL CHECKSUM: {:#016x}   [PE & VM PROTECTED]", final_checksum),
        rgb(255, 215, 0),
    );

    // 6. Draw Telemetry Protection Stages Panel (Right Overlay)
    draw_rect(hdc, 570, 90, 790, 580, rgb(15, 22, 35));
    draw_rect(hdc, 570, 90, 790, 115, rgb(30, 45, 70));
    draw_text(hdc, 580, 95, "PROTECTION STAGES (15)", rgb(0, 255, 180));

    for (idx, (name, hash)) in stage_results.iter().enumerate() {
        let y_pos = 122 + (idx as i32 * 30);
        // Stage Status Badge (Green PASS)
        draw_rect(hdc, 580, y_pos, 600, y_pos + 18, rgb(0, 200, 100));
        draw_text(hdc, 582, y_pos + 2, "OK", rgb(255, 255, 255));

        // Stage Name & Hash
        draw_text(hdc, 608, y_pos + 1, name, rgb(220, 220, 220));
        draw_text(
            hdc,
            608,
            y_pos + 14,
            &format!("{:#010x}", (hash & 0xFFFFFFFF) as u32),
            rgb(120, 180, 255),
        );
    }

    black_box(());
}
