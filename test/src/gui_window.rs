use crate::game_engine::{CyberDefenderGame, GAME_HEIGHT, GAME_WIDTH};
use crate::gui_overlay::render_game_and_telemetry_hud;
use crate::win32_ffi::*;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering};

static IS_RUNNING: AtomicBool = AtomicBool::new(true);

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: UINT,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_DESTROY | WM_CLOSE => {
            IS_RUNNING.store(false, Ordering::SeqCst);
            PostQuitMessage(0);
            0
        }
        WM_ERASEBKGND => 1, // Suppress background erase to eliminate flicker
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[inline(never)]
pub fn launch_gui_window(
    stage_results: &[(&'static str, u64); 15],
    final_checksum: u64,
    auto_close_frames: Option<u32>,
) {
    unsafe {
        let hinstance = GetModuleHandleW(std::ptr::null());
        let class_name = "BTG_Packer_Test_GUI_Class\0".encode_utf16().collect::<Vec<u16>>();
        let window_title = "BTG Cyber Defender & Protection Telemetry HUD v3.0\0"
            .encode_utf16()
            .collect::<Vec<u16>>();

        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as UINT,
            style: 0,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: std::ptr::null_mut(),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };

        RegisterClassExW(&wc);

        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            window_title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            GAME_WIDTH + 16,
            GAME_HEIGHT + 39,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinstance,
            std::ptr::null_mut(),
        );

        if hwnd.is_null() {
            println!("[-] Failed to create Win32 GUI window.");
            return;
        }

        ShowWindow(hwnd, 1);
        UpdateWindow(hwnd);

        // GDI Setup & Double-Buffering
        let hdc_win = BeginPaint(hwnd, &mut PAINTSTRUCT {
            hdc: std::ptr::null_mut(),
            fErase: 0,
            rcPaint: RECT { left: 0, top: 0, right: 0, bottom: 0 },
            fRestore: 0,
            fIncUpdate: 0,
            rgbReserved: [0; 32],
        });

        let hdc_mem = CreateCompatibleDC(hdc_win);
        let hbmp_mem = CreateCompatibleBitmap(hdc_win, GAME_WIDTH, GAME_HEIGHT);
        SelectObject(hdc_mem, hbmp_mem);

        let mut game = CyberDefenderGame::new(final_checksum);
        let mut msg: MSG = std::mem::zeroed();

        println!("[+] Win32 GUI Window & Game Loop initialized successfully.");

        let mut frame_count = 0u32;
        let is_auto_close = auto_close_frames.is_some();
        let max_frames = auto_close_frames.unwrap_or(u32::MAX);

        while IS_RUNNING.load(Ordering::SeqCst) && frame_count < max_frames {
            // Process Windows Messages
            while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                if msg.message == WM_QUIT {
                    IS_RUNNING.store(false, Ordering::SeqCst);
                    break;
                }

                // Keyboard Controls for Player Drone
                if msg.message == WM_KEYDOWN {
                    match msg.wParam {
                        VK_LEFT | VK_KEY_A => game.move_player(-1, 0),
                        VK_RIGHT | VK_KEY_D => game.move_player(1, 0),
                        VK_UP | VK_KEY_W => game.move_player(0, -1),
                        VK_DOWN | VK_KEY_S => game.move_player(0, 1),
                        VK_ESCAPE => IS_RUNNING.store(false, Ordering::SeqCst),
                        _ => {}
                    }
                }

                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            // Step Game Engine State (AI auto-play enabled if auto_close requested)
            game.step(is_auto_close);

            // Render Frame to Double-Buffer Memory DC
            render_game_and_telemetry_hud(hdc_mem, &game, stage_results, final_checksum);

            // Blit Memory DC to Window Screen DC
            BitBlt(hdc_win, 0, 0, GAME_WIDTH, GAME_HEIGHT, hdc_mem, 0, 0, SRCCOPY);

            frame_count += 1;
            std::thread::sleep(std::time::Duration::from_millis(16)); // ~60 FPS
        }

        // Cleanup GDI Handles
        DeleteObject(hbmp_mem);
        DeleteDC(hdc_mem);
        EndPaint(hwnd, &PAINTSTRUCT {
            hdc: hdc_win,
            fErase: 0,
            rcPaint: RECT { left: 0, top: 0, right: 0, bottom: 0 },
            fRestore: 0,
            fIncUpdate: 0,
            rgbReserved: [0; 32],
        });

        black_box(());
    }
}
