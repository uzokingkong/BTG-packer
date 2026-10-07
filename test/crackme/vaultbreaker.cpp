// ============================================================================
// BTG VaultBreaker — a GUI keygen-me / crackme challenge game.
// ----------------------------------------------------------------------------
// Two run modes share ONE validation core so the Program-VM lift and the human
// game exercise identical code:
//
//   * default (double-click / no args) -> Win32 GUI game.
//       Three vault stages. Type the key that hashes to the stage target to
//       advance. Clear all three to breach the vault.
//
//   * `--headless`                      -> deterministic console battery.
//       Runs a fixed set of keys through the SAME validator, prints each hash
//       and the per-stage verdict, then exits 0. This is the finite, stdout-
//       stable path that `btg-packer --verify-output` diffs original vs packed.
//
// Build (MSVC, console subsystem so --headless stdout is pipe-capturable):
//   cl /O2 /EHsc /std:c++17 vaultbreaker.cpp /link user32.lib gdi32.lib
//
// NOTE: the validation core is deliberately plain integer arithmetic/control
// flow (no SEH, no heap tricks) so it lifts cleanly into the VM; the GUI shell
// stays native. The targets below were produced by the reference oracle for
// the shipped solution keys, so the game is solvable:
//   stage 1  "BTG-2024-ALPHA"  -> 0x906666DB
//   stage 2  "V4ULT-BR34K3R"   -> 0x993713FD
//   stage 3  "0xC0FFEE-GAME"   -> 0x1F2B28BA
// ============================================================================
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ---- validation core (shared, VM-lift target) -----------------------------

// One mixing round. Kept as a separate function so the lifter sees a reusable
// leaf with a tight arithmetic/rotate/multiply chain.
static uint32_t stage_mix(uint32_t acc, uint32_t c, int i) {
    acc ^= c + (uint32_t)((uint32_t)i * 0x9E3779B1u);
    acc = (acc << 7) | (acc >> 25);   // rotl32(acc, 7)
    acc *= 0x01000193u;               // FNV-1a prime
    acc += (acc >> 11);
    return acc;
}

// FNV-seeded rolling hash over the key bytes.
static uint32_t compute_hash(const char* key) {
    uint32_t acc = 0x811C9DC5u;
    for (int i = 0; key[i] != '\0'; ++i) {
        acc = stage_mix(acc, (uint8_t)key[i], i);
    }
    return acc;
}

static const uint32_t kStageTarget[3] = {
    0x906666DBu,  // "BTG-2024-ALPHA"
    0x993713FDu,  // "V4ULT-BR34K3R"
    0x1F2B28BAu,  // "0xC0FFEE-GAME"
};

static int key_clears_stage(const char* key, int stage /*0..2*/) {
    if (stage < 0 || stage > 2) return 0;
    return compute_hash(key) == kStageTarget[stage] ? 1 : 0;
}

// ---- headless battery (deterministic, what --verify-output diffs) ----------

static int run_headless(void) {
    struct { const char* key; int stage; } battery[] = {
        { "BTG-2024-ALPHA", 0 },
        { "V4ULT-BR34K3R",  1 },
        { "0xC0FFEE-GAME",  2 },
        { "wrong",          0 },
        { "admin",          1 },
    };
    const int n = (int)(sizeof(battery) / sizeof(battery[0]));
    int cleared = 0;
    printf("BTG VaultBreaker headless battery\n");
    for (int i = 0; i < n; ++i) {
        uint32_t h = compute_hash(battery[i].key);
        int ok = key_clears_stage(battery[i].key, battery[i].stage);
        cleared += ok;
        printf("stage %d  key=%-16s hash=0x%08X  %s\n",
               battery[i].stage + 1, battery[i].key, h, ok ? "CLEAR" : "deny");
    }
    printf("cleared=%d/3\n", cleared);
    // Deterministic, identical for original and packed images.
    return 0;
}

// ---- Win32 GUI game --------------------------------------------------------

enum { ID_EDIT = 1001, ID_UNLOCK = 1002, ID_STATUS = 1003, ID_LEVEL = 1004 };

static int g_stage = 0;        // current stage 0..2, 3 == breached
static HFONT g_font = NULL;
static HWND g_edit, g_status, g_level, g_unlock;

static void refresh_labels(HWND hwnd) {
    char buf[128];
    if (g_stage >= 3) {
        SetWindowTextA(g_level, "VAULT BREACHED");
        SetWindowTextA(g_status, "All three locks are open. You win.");
        EnableWindow(g_edit, FALSE);
        EnableWindow(g_unlock, FALSE);
    } else {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "VAULT LOCK %d / 3  (target 0x%08X)",
                    g_stage + 1, kStageTarget[g_stage]);
        SetWindowTextA(g_level, buf);
    }
    InvalidateRect(hwnd, NULL, TRUE);
}

static void on_unlock(HWND hwnd) {
    char key[128] = {0};
    GetWindowTextA(g_edit, key, sizeof(key) - 1);
    char msg[192];
    if (key_clears_stage(key, g_stage)) {
        ++g_stage;
        SetWindowTextA(g_edit, "");
        if (g_stage >= 3) {
            refresh_labels(hwnd);
            return;
        }
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                    "Lock %d open. Two... one more to go.", g_stage);
        SetWindowTextA(g_status, msg);
    } else {
        uint32_t h = compute_hash(key);
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                    "Denied. your key -> 0x%08X   (keep trying)", h);
        SetWindowTextA(g_status, msg);
    }
    refresh_labels(hwnd);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_font = CreateFontA(-16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                             ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, FF_DONTCARE, "Consolas");
        g_level = CreateWindowA("STATIC", "VAULT LOCK 1 / 3",
                    WS_CHILD | WS_VISIBLE | SS_CENTER,
                    20, 20, 420, 28, hwnd, (HMENU)ID_LEVEL, NULL, NULL);
        CreateWindowA("STATIC", "Enter the access key:",
                    WS_CHILD | WS_VISIBLE,
                    20, 66, 420, 22, hwnd, NULL, NULL, NULL);
        g_edit = CreateWindowA("EDIT", "",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                    20, 92, 420, 28, hwnd, (HMENU)ID_EDIT, NULL, NULL);
        g_unlock = CreateWindowA("BUTTON", "UNLOCK",
                    WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                    20, 132, 420, 34, hwnd, (HMENU)ID_UNLOCK, NULL, NULL);
        g_status = CreateWindowA("STATIC", "Three locks stand between you and the vault.",
                    WS_CHILD | WS_VISIBLE,
                    20, 178, 420, 48, hwnd, (HMENU)ID_STATUS, NULL, NULL);
        HWND ctrls[4] = { g_level, g_edit, g_unlock, g_status };
        for (int i = 0; i < 4; ++i)
            SendMessageA(ctrls[i], WM_SETFONT, (WPARAM)g_font, TRUE);
        refresh_labels(hwnd);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == ID_UNLOCK && HIWORD(wp) == BN_CLICKED) {
            on_unlock(hwnd);
            return 0;
        }
        break;
    case WM_DESTROY:
        if (g_font) DeleteObject(g_font);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static int run_gui(void) {
    HINSTANCE hinst = GetModuleHandleA(NULL);
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hinst;
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "BTGVaultBreaker";
    if (!RegisterClassA(&wc)) return 2;

    HWND hwnd = CreateWindowA(wc.lpszClassName, "BTG VaultBreaker",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 480, 290,
        NULL, NULL, hinst, NULL);
    if (!hwnd) return 2;
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG m;
    while (GetMessageA(&m, NULL, 0, 0) > 0) {
        if (m.message == WM_KEYDOWN && m.wParam == VK_ESCAPE) break;
        if (!IsDialogMessageA(hwnd, &m)) {
            TranslateMessage(&m);
            DispatchMessageA(&m);
        }
    }
    return 0;
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--headless") == 0) {
            return run_headless();
        }
    }
    // Interactive game: hide the console the console-subsystem build opened.
    FreeConsole();
    return run_gui();
}
