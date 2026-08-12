#![allow(dead_code, non_snake_case, non_camel_case_types)]

pub type BOOL = i32;
pub type UINT = u32;
pub type DWORD = u32;
pub type WORD = u16;
pub type BYTE = u8;
pub type LONG = i32;
pub type ULONG_PTR = usize;
pub type LRESULT = isize;
pub type LPARAM = isize;
pub type WPARAM = usize;
pub type HANDLE = *mut std::ffi::c_void;
pub type HWND = HANDLE;
pub type HDC = HANDLE;
pub type HBITMAP = HANDLE;
pub type HBRUSH = HANDLE;
pub type HPEN = HANDLE;
pub type HFONT = HANDLE;
pub type HICON = HANDLE;
pub type HCURSOR = HANDLE;
pub type HINSTANCE = HANDLE;
pub type HMODULE = HANDLE;
pub type WNDPROC = Option<unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT>;

pub const FALSE: BOOL = 0;
pub const TRUE: BOOL = 1;

pub const WS_OVERLAPPED: DWORD = 0x00000000;
pub const WS_CAPTION: DWORD = 0x00C00000;
pub const WS_SYSMENU: DWORD = 0x00080000;
pub const WS_THICKFRAME: DWORD = 0x00040000;
pub const WS_MINIMIZEBOX: DWORD = 0x00020000;
pub const WS_MAXIMIZEBOX: DWORD = 0x00010000;
pub const WS_OVERLAPPEDWINDOW: DWORD =
    WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;
pub const WS_VISIBLE: DWORD = 0x10000000;

pub const CW_USEDEFAULT: i32 = 0x80000000u32 as i32;

pub const WM_DESTROY: UINT = 0x0002;
pub const WM_SIZE: UINT = 0x0005;
pub const WM_PAINT: UINT = 0x000F;
pub const WM_CLOSE: UINT = 0x0010;
pub const WM_QUIT: UINT = 0x0012;
pub const WM_ERASEBKGND: UINT = 0x0014;
pub const WM_KEYDOWN: UINT = 0x0100;
pub const WM_KEYUP: UINT = 0x0101;
pub const WM_TIMER: UINT = 0x0113;

pub const VK_LEFT: usize = 0x25;
pub const VK_UP: usize = 0x26;
pub const VK_RIGHT: usize = 0x27;
pub const VK_DOWN: usize = 0x28;
pub const VK_SPACE: usize = 0x20;
pub const VK_KEY_A: usize = 0x41;
pub const VK_KEY_D: usize = 0x44;
pub const VK_KEY_W: usize = 0x57;
pub const VK_KEY_S: usize = 0x53;
pub const VK_ESCAPE: usize = 0x1B;

pub const COLOR_WINDOW: i32 = 5;
pub const IDC_ARROW: *const u16 = 32512 as *const u16;

pub const PM_REMOVE: UINT = 0x0001;

pub const SRCCOPY: DWORD = 0x00CC0020;
pub const TRANSPARENT: i32 = 1;

#[repr(C)]
pub struct POINT {
    pub x: LONG,
    pub y: LONG,
}

#[repr(C)]
pub struct RECT {
    pub left: LONG,
    pub top: LONG,
    pub right: LONG,
    pub bottom: LONG,
}

#[repr(C)]
pub struct MSG {
    pub hwnd: HWND,
    pub message: UINT,
    pub wParam: WPARAM,
    pub lParam: LPARAM,
    pub time: DWORD,
    pub pt: POINT,
}

#[repr(C)]
pub struct WNDCLASSEXW {
    pub cbSize: UINT,
    pub style: UINT,
    pub lpfnWndProc: WNDPROC,
    pub cbClsExtra: i32,
    pub cbWndExtra: i32,
    pub hInstance: HINSTANCE,
    pub hIcon: HICON,
    pub hCursor: HCURSOR,
    pub hbrBackground: HBRUSH,
    pub lpszMenuName: *const u16,
    pub lpszClassName: *const u16,
    pub hIconSm: HICON,
}

#[repr(C)]
pub struct PAINTSTRUCT {
    pub hdc: HDC,
    pub fErase: BOOL,
    pub rcPaint: RECT,
    pub fRestore: BOOL,
    pub fIncUpdate: BOOL,
    pub rgbReserved: [BYTE; 32],
}

#[link(name = "user32")]
#[link(name = "gdi32")]
#[link(name = "kernel32")]
extern "system" {
    pub fn GetModuleHandleW(lpModuleName: *const u16) -> HMODULE;
    pub fn RegisterClassExW(unnamed1: *const WNDCLASSEXW) -> WORD;
    pub fn CreateWindowExW(
        dwExStyle: DWORD,
        lpClassName: *const u16,
        lpWindowName: *const u16,
        dwStyle: DWORD,
        X: i32,
        Y: i32,
        nWidth: i32,
        nHeight: i32,
        hWndParent: HWND,
        hMenu: HANDLE,
        hInstance: HINSTANCE,
        lpParam: *mut std::ffi::c_void,
    ) -> HWND;
    pub fn ShowWindow(hWnd: HWND, nCmdShow: i32) -> BOOL;
    pub fn UpdateWindow(hWnd: HWND) -> BOOL;
    pub fn PeekMessageW(
        lpMsg: *mut MSG,
        hWnd: HWND,
        wMsgFilterMin: UINT,
        wMsgFilterMax: UINT,
        wRemoveMsg: UINT,
    ) -> BOOL;
    pub fn TranslateMessage(lpMsg: *const MSG) -> BOOL;
    pub fn DispatchMessageW(lpMsg: *const MSG) -> LRESULT;
    pub fn PostQuitMessage(nExitCode: i32);
    pub fn DefWindowProcW(hWnd: HWND, Msg: UINT, wParam: WPARAM, lParam: LPARAM) -> LRESULT;
    pub fn LoadCursorW(hInstance: HINSTANCE, lpCursorName: *const u16) -> HCURSOR;

    pub fn BeginPaint(hWnd: HWND, lpPaint: *mut PAINTSTRUCT) -> HDC;
    pub fn EndPaint(hWnd: HWND, lpPaint: *const PAINTSTRUCT) -> BOOL;
    pub fn GetClientRect(hWnd: HWND, lpRect: *mut RECT) -> BOOL;

    pub fn CreateCompatibleDC(hdc: HDC) -> HDC;
    pub fn CreateCompatibleBitmap(hdc: HDC, cx: i32, cy: i32) -> HBITMAP;
    pub fn SelectObject(hdc: HDC, h: HANDLE) -> HANDLE;
    pub fn DeleteObject(ho: HANDLE) -> BOOL;
    pub fn DeleteDC(hdc: HDC) -> BOOL;
    pub fn BitBlt(
        hdc: HDC,
        x: i32,
        y: i32,
        cx: i32,
        cy: i32,
        hdcSrc: HDC,
        x1: i32,
        y1: i32,
        rop: DWORD,
    ) -> BOOL;

    pub fn CreateSolidBrush(color: DWORD) -> HBRUSH;
    pub fn CreatePen(iStyle: i32, cWidth: i32, color: DWORD) -> HPEN;
    pub fn FillRect(hDC: HDC, lprc: *const RECT, hbr: HBRUSH) -> i32;
    pub fn Rectangle(hdc: HDC, left: i32, top: i32, right: i32, bottom: i32) -> BOOL;
    pub fn SetTextColor(hdc: HDC, color: DWORD) -> DWORD;
    pub fn SetBkMode(hdc: HDC, mode: i32) -> i32;
    pub fn TextOutW(hdc: HDC, x: i32, y: i32, lpString: *const u16, c: i32) -> BOOL;
    pub fn SetTimer(hWnd: HWND, nIDEvent: usize, uElapse: UINT, lpTimerFunc: HANDLE) -> usize;
    pub fn KillTimer(hWnd: HWND, uIDEvent: usize) -> BOOL;
    pub fn InvalidateRect(hWnd: HWND, lpRect: *const RECT, bErase: BOOL) -> BOOL;
}

pub fn rgb(r: u8, g: u8, b: u8) -> DWORD {
    (r as DWORD) | ((g as DWORD) << 8) | ((b as DWORD) << 16)
}
