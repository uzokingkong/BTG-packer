// ==============================================================================
// BTG CLI Progress Engine
// ==============================================================================
//
// Process-global, dependency-free progress telemetry for long packing runs.
// The renderer keeps an exact item counter, a weighted overall percentage,
// throughput, elapsed time and ETA. TTYs are updated in-place; redirected
// output is rate-limited to milestone lines so CI logs remain readable.
// ==============================================================================

use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct ProgressState {
    enabled: bool,
    tty: bool,
    single_line: bool,
    refresh: Duration,
    started: Instant,
    phase_started: Instant,
    task_started: Instant,
    root_base_bp: u32,
    root_span_bp: u32,
    active_base_bp: u32,
    active_span_bp: u32,
    overall_bp: u32,
    phase: String,
    task: String,
    unit: String,
    position: u64,
    total: u64,
    task_affects_overall: bool,
    last_render: Instant,
    last_line_len: usize,
    last_log_bucket: u32,
}

impl Default for ProgressState {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            enabled: false,
            tty: io::stderr().is_terminal(),
            single_line: false,
            refresh: Duration::from_millis(80),
            started: now,
            phase_started: now,
            task_started: now,
            root_base_bp: 0,
            root_span_bp: 0,
            active_base_bp: 0,
            active_span_bp: 0,
            overall_bp: 0,
            phase: String::new(),
            task: String::new(),
            unit: String::new(),
            position: 0,
            total: 0,
            task_affects_overall: true,
            last_render: now,
            last_line_len: 0,
            last_log_bucket: u32::MAX,
        }
    }
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static PROGRESS_ONLY: AtomicBool = AtomicBool::new(false);
static STATE: OnceLock<Mutex<ProgressState>> = OnceLock::new();

fn state() -> &'static Mutex<ProgressState> {
    STATE.get_or_init(|| Mutex::new(ProgressState::default()))
}

pub fn configure(enabled: bool, refresh_ms: u64, progress_only: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
    PROGRESS_ONLY.store(enabled && progress_only, Ordering::Relaxed);
    let mut s = state().lock().expect("progress mutex poisoned");
    let now = Instant::now();
    s.enabled = enabled;
    s.tty = io::stderr().is_terminal();
    s.single_line = enabled && progress_only;
    s.refresh = Duration::from_millis(refresh_ms.clamp(16, 2_000));
    s.started = now;
    s.phase_started = now;
    s.task_started = now;
    s.root_base_bp = 0;
    s.root_span_bp = 0;
    s.active_base_bp = 0;
    s.active_span_bp = 0;
    s.overall_bp = 0;
    s.phase.clear();
    s.task.clear();
    s.unit.clear();
    s.position = 0;
    s.total = 0;
    s.task_affects_overall = true;
    s.last_render = now.checked_sub(s.refresh).unwrap_or(now);
    s.last_line_len = 0;
    s.last_log_bucket = u32::MAX;
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// True when the CLI requested a clean console containing only the live gauge.
pub fn progress_only() -> bool {
    PROGRESS_ONLY.load(Ordering::Relaxed)
}

/// stderr diagnostic that disappears while --progress-only owns the console.
#[macro_export]
macro_rules! progress_safe_eprintln {
    ($($arg:tt)*) => {{
        if !$crate::progress::progress_only() {
            eprintln!($($arg)*);
        }
    }};
}

/// Start a weighted top-level phase. Values are basis points: 0..=10000.
pub fn begin_phase(base_bp: u32, span_bp: u32, label: impl Into<String>) {
    if !enabled() {
        return;
    }
    let mut s = state().lock().expect("progress mutex poisoned");
    if !s.enabled {
        return;
    }
    let now = Instant::now();
    s.root_base_bp = base_bp.min(10_000);
    s.root_span_bp = span_bp.min(10_000 - s.root_base_bp);
    s.active_base_bp = s.root_base_bp;
    s.active_span_bp = s.root_span_bp;
    s.overall_bp = s.overall_bp.max(s.root_base_bp);
    s.phase = label.into();
    s.phase_started = now;
    s.task_started = now;
    s.task.clear();
    s.unit.clear();
    s.position = 0;
    s.total = 0;
    s.task_affects_overall = true;
    render_locked(&mut s, true);
    finalize_tty_line(&mut s, false);
}

/// Select a weighted sub-range within the current top-level phase.
/// rel_base_bp/rel_span_bp are relative basis points (0..=10000).
pub fn subphase(rel_base_bp: u32, rel_span_bp: u32, label: impl Into<String>) {
    if !enabled() {
        return;
    }
    let mut s = state().lock().expect("progress mutex poisoned");
    if !s.enabled {
        return;
    }
    let rel_base = rel_base_bp.min(10_000);
    let rel_span = rel_span_bp.min(10_000 - rel_base);
    let base = s.root_base_bp + ((u64::from(s.root_span_bp) * u64::from(rel_base)) / 10_000) as u32;
    let span = ((u64::from(s.root_span_bp) * u64::from(rel_span)) / 10_000) as u32;
    s.active_base_bp = base;
    s.active_span_bp = span;
    s.overall_bp = s.overall_bp.max(base);
    s.task = label.into();
    s.task_started = Instant::now();
    s.position = 0;
    s.total = 0;
    s.unit.clear();
    s.task_affects_overall = true;
    render_locked(&mut s, true);
    finalize_tty_line(&mut s, false);
}

pub fn begin_task(label: impl Into<String>, total: u64, unit: impl Into<String>) {
    begin_task_inner(label.into(), total, unit.into(), true);
}

/// Start an exact local counter without moving the weighted overall percentage.
/// Use this for nested scans inside a larger weighted phase.
pub fn begin_detail_task(label: impl Into<String>, total: u64, unit: impl Into<String>) {
    begin_task_inner(label.into(), total, unit.into(), false);
}

fn begin_task_inner(label: String, total: u64, unit: String, affects_overall: bool) {
    if !enabled() {
        return;
    }
    let mut s = state().lock().expect("progress mutex poisoned");
    if !s.enabled {
        return;
    }
    s.task = label;
    s.unit = unit;
    s.position = 0;
    s.total = total;
    s.task_affects_overall = affects_overall;
    s.task_started = Instant::now();
    render_locked(&mut s, true);
}

pub fn set_position(position: u64) {
    if !enabled() {
        return;
    }
    let mut s = state().lock().expect("progress mutex poisoned");
    if !s.enabled {
        return;
    }
    s.position = if s.total == 0 {
        position
    } else {
        position.min(s.total)
    };
    if s.total != 0 && s.task_affects_overall {
        let local =
            (u128::from(s.active_span_bp) * u128::from(s.position) / u128::from(s.total)) as u32;
        s.overall_bp = s.overall_bp.max((s.active_base_bp + local).min(10_000));
    }
    render_locked(&mut s, false);
}

pub fn inc(delta: u64) {
    if !enabled() {
        return;
    }
    let next = {
        let s = state().lock().expect("progress mutex poisoned");
        if !s.enabled {
            return;
        }
        s.position.saturating_add(delta)
    };
    set_position(next);
}

pub fn set_task(label: impl Into<String>) {
    if !enabled() {
        return;
    }
    let mut s = state().lock().expect("progress mutex poisoned");
    if !s.enabled {
        return;
    }
    s.task = label.into();
    render_locked(&mut s, true);
}

pub fn finish_task(label: impl Into<String>) {
    if !enabled() {
        return;
    }
    let mut s = state().lock().expect("progress mutex poisoned");
    if !s.enabled {
        return;
    }
    if s.total != 0 {
        s.position = s.total;
        if s.task_affects_overall {
            s.overall_bp = s
                .overall_bp
                .max((s.active_base_bp + s.active_span_bp).min(10_000));
        }
    }
    s.task = label.into();
    render_locked(&mut s, true);
    finalize_tty_line(&mut s, false);
}

/// Force the overall position to a completed milestone (basis points).
pub fn checkpoint(overall_bp: u32, label: impl Into<String>) {
    if !enabled() {
        return;
    }
    let mut s = state().lock().expect("progress mutex poisoned");
    if !s.enabled {
        return;
    }
    s.overall_bp = s.overall_bp.max(overall_bp.min(10_000));
    s.phase = label.into();
    s.task.clear();
    s.position = 0;
    s.total = 0;
    s.unit.clear();
    render_locked(&mut s, true);
    finalize_tty_line(&mut s, false);
}

pub fn complete(label: impl Into<String>) {
    if !enabled() {
        return;
    }
    let mut s = state().lock().expect("progress mutex poisoned");
    if !s.enabled {
        return;
    }
    s.overall_bp = 10_000;
    s.phase = label.into();
    s.task.clear();
    s.position = 0;
    s.total = 0;
    s.unit.clear();
    render_locked(&mut s, true);
    finalize_tty_line(&mut s, true);
}

/// Finish an active in-place line without changing progress state.
/// Used by CLI RAII so errors are printed on a fresh line.
pub fn finish_console_line() {
    if !enabled() {
        return;
    }
    let mut s = state().lock().expect("progress mutex poisoned");
    if s.tty && s.last_line_len != 0 {
        eprintln!();
        s.last_line_len = 0;
    }
}

fn finalize_tty_line(s: &mut ProgressState, final_line: bool) {
    if s.tty && (!s.single_line || final_line) {
        eprintln!();
        s.last_line_len = 0;
    }
}

fn render_locked(s: &mut ProgressState, force: bool) {
    if !s.enabled {
        return;
    }

    let now = Instant::now();
    if !force && now.duration_since(s.last_render) < s.refresh {
        return;
    }

    let bucket = s.overall_bp / 250; // 2.5% buckets for redirected logs.
    if !s.tty && !force && bucket == s.last_log_bucket {
        return;
    }

    let width = 32usize;
    let local_fraction = if s.total == 0 {
        f64::from(s.overall_bp) / 10_000.0
    } else {
        (s.position as f64 / s.total as f64).clamp(0.0, 1.0)
    };
    let bar = if s.tty {
        render_unicode_bar(local_fraction, width)
    } else {
        render_ascii_bar(local_fraction, width)
    };
    let overall = f64::from(s.overall_bp) / 100.0;
    let overall_fraction = f64::from(s.overall_bp) / 10_000.0;
    let local_percent = local_fraction * 100.0;
    let elapsed = now.duration_since(s.started);
    let overall_eta =
        if overall_fraction > 0.01 && overall_fraction < 1.0 && elapsed.as_secs_f64() >= 1.0 {
            Some(Duration::from_secs_f64(
                elapsed.as_secs_f64() * (1.0 - overall_fraction) / overall_fraction,
            ))
        } else {
            None
        };
    let overall_eta_text = overall_eta
        .map(format_duration)
        .unwrap_or_else(|| "--:--".to_string());

    let detail = if s.total != 0 {
        let task_elapsed = now.duration_since(s.task_started).as_secs_f64();
        let rate = if task_elapsed > 0.05 {
            s.position as f64 / task_elapsed
        } else {
            0.0
        };
        let eta = if rate > 0.0 && s.position < s.total {
            Some(Duration::from_secs_f64(
                (s.total - s.position) as f64 / rate,
            ))
        } else {
            None
        };
        format!(
            "{} | {}/{} {} | {}/s | ETA {}",
            if s.task.is_empty() { &s.phase } else { &s.task },
            format_count(s.position),
            format_count(s.total),
            s.unit,
            format_rate(rate),
            eta.map(format_duration)
                .unwrap_or_else(|| "--:--".to_string()),
        )
    } else if s.task.is_empty() {
        s.phase.clone()
    } else {
        format!("{} | {}", s.phase, s.task)
    };

    let line = if s.total != 0 {
        format!(
            "[{}] task {:>6.2}% | overall {:>6.2}% | {} | total ETA ~{} | elapsed {}",
            bar,
            local_percent,
            overall,
            detail,
            overall_eta_text,
            format_duration(elapsed),
        )
    } else {
        format!(
            "[{}] overall {:>6.2}% | {} | total ETA ~{} | elapsed {}",
            bar,
            overall,
            detail,
            overall_eta_text,
            format_duration(elapsed),
        )
    };

    if s.tty {
        let pad = s.last_line_len.saturating_sub(line.chars().count());
        eprint!("\r{}{}", line, " ".repeat(pad));
        let _ = io::stderr().flush();
        s.last_line_len = line.chars().count();
    } else {
        eprintln!("[PROGRESS] {}", line);
        s.last_log_bucket = bucket;
    }
    s.last_render = now;
}

fn render_ascii_bar(fraction: f64, width: usize) -> String {
    let filled = (fraction.clamp(0.0, 1.0) * width as f64).floor() as usize;
    format!(
        "{}{}",
        "=".repeat(filled.min(width)),
        "-".repeat(width.saturating_sub(filled))
    )
}

/// Render a high-resolution terminal bar using Unicode block elements.
/// Each cell has 8 sub-steps: ▏▎▍▌▋▊▉█.
fn render_unicode_bar(fraction: f64, width: usize) -> String {
    const PARTIAL: [char; 8] = [' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉'];

    let clamped = fraction.clamp(0.0, 1.0);
    let eighths = (clamped * width as f64 * 8.0).round() as usize;
    let full = (eighths / 8).min(width);
    let partial = eighths % 8;

    let mut out = String::with_capacity(width * 3);
    out.push_str(&"█".repeat(full));

    if full < width {
        if partial != 0 {
            out.push(PARTIAL[partial]);
        } else {
            out.push('░');
        }
        let used = full + 1;
        if used < width {
            out.push_str(&"░".repeat(width - used));
        }
    }

    out
}

fn format_count(value: u64) -> String {
    let raw = value.to_string();
    let mut out = String::with_capacity(raw.len() + raw.len() / 3);
    for (index, ch) in raw.chars().enumerate() {
        if index != 0 && (raw.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn format_rate(rate: f64) -> String {
    if rate >= 1000.0 {
        format!("{:.1}k", rate / 1000.0)
    } else if rate >= 100.0 {
        format!("{:.0}", rate)
    } else if rate >= 10.0 {
        format!("{:.1}", rate)
    } else if rate > 0.0 {
        format!("{:.2}", rate)
    } else {
        "--".to_string()
    }
}

fn format_duration(duration: Duration) -> String {
    let total = duration.as_secs();
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;
    if hours > 0 {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::{render_ascii_bar, render_unicode_bar};

    #[test]
    fn unicode_bar_has_fixed_cell_width_and_partial_resolution() {
        let bar = render_unicode_bar(0.3827, 32);
        assert_eq!(bar.chars().count(), 32);
        assert!(bar.contains('█'));
        assert!(bar
            .chars()
            .any(|ch| matches!(ch, '▏' | '▎' | '▍' | '▌' | '▋' | '▊' | '▉')));
        assert!(bar.contains('░'));
    }

    #[test]
    fn unicode_bar_handles_empty_and_complete() {
        assert_eq!(render_unicode_bar(0.0, 8), "░░░░░░░░");
        assert_eq!(render_unicode_bar(1.0, 8), "████████");
    }

    #[test]
    fn redirected_bar_keeps_ascii_fallback() {
        assert_eq!(render_ascii_bar(0.5, 8), "====----");
    }
}
