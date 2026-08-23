//! Process-isolated boundary for executing native VM probes.
//!
//! Hardware exceptions raised by generated code are not Rust panics.  Calling
//! such code behind `catch_unwind` would still terminate the packer/test
//! process.  This module therefore provides a deliberately process-based
//! boundary.  A small helper executable owns the unsafe native call; its
//! Windows exception termination status is normalized here.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Guest-side location known immediately before entering generated code.
///
/// The host OS only guarantees an exception status at this process boundary.
/// Supplying the last committed guest location keeps diagnostics deterministic
/// without pretending that it is the native exception RIP.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeGuestContext {
    pub guest_vip: u64,
    pub guest_rip: u64,
    pub instruction_index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeGuestFaultKind {
    DivideError,
    IllegalInstruction,
    AccessViolation,
    StackOverflow,
    UnknownOsException(u32),
    AbnormalTermination,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeGuestFault {
    pub kind: NativeGuestFaultKind,
    pub context: NativeGuestContext,
    /// Windows NTSTATUS when available.  This is not the native exception RIP.
    pub os_exception_code: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeIsolatedResult {
    Completed { exit_code: i32 },
    Fault(NativeGuestFault),
    TimedOut { context: NativeGuestContext },
}

/// Execute a native-probe helper in a child process.
///
/// `program` must be a trusted helper that performs the generated-code call.
/// Output is suppressed so arbitrary guest bytes cannot corrupt the parent's
/// protocol.  Existing in-process runner APIs remain unchanged.
pub fn run_native_isolated<I, S>(
    program: impl AsRef<Path>,
    args: I,
    context: NativeGuestContext,
    timeout: Duration,
) -> Result<NativeIsolatedResult>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut child = Command::new(program.as_ref())
        .args(args.into_iter().map(Into::into))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| {
            format!(
                "failed to start native VM helper {}",
                program.as_ref().display()
            )
        })?;

    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to wait for native VM helper")?
        {
            return Ok(classify_native_exit(status.code(), context));
        }
        if started.elapsed() >= timeout {
            // The child is the isolation boundary and may contain arbitrary
            // generated code, so forcibly terminating it is intentional.
            let _ = child.kill();
            let _ = child.wait();
            return Ok(NativeIsolatedResult::TimedOut { context });
        }
        thread::sleep(Duration::from_millis(2));
    }
}

/// Normalize a portable `ExitStatus::code()` value.  Windows exposes an
/// unhandled exception NTSTATUS through this value (represented as signed
/// `i32` by Rust), while Unix signal deaths have no code.
pub fn classify_native_exit(
    exit_code: Option<i32>,
    context: NativeGuestContext,
) -> NativeIsolatedResult {
    let Some(signed) = exit_code else {
        return NativeIsolatedResult::Fault(NativeGuestFault {
            kind: NativeGuestFaultKind::AbnormalTermination,
            context,
            os_exception_code: None,
        });
    };
    if signed == 0 {
        return NativeIsolatedResult::Completed { exit_code: 0 };
    }

    let raw = signed as u32;
    let kind = match raw {
        0xC000_0094 | 0xC000_008E | 0xC000_0095 => NativeGuestFaultKind::DivideError,
        0xC000_001D => NativeGuestFaultKind::IllegalInstruction,
        0xC000_0005 => NativeGuestFaultKind::AccessViolation,
        0xC000_00FD => NativeGuestFaultKind::StackOverflow,
        // Ordinary non-zero helper exit codes are not OS exceptions.
        1..=0x3FFF_FFFF => {
            return NativeIsolatedResult::Completed { exit_code: signed };
        }
        _ => NativeGuestFaultKind::UnknownOsException(raw),
    };
    NativeIsolatedResult::Fault(NativeGuestFault {
        kind,
        context,
        os_exception_code: Some(raw),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> NativeGuestContext {
        NativeGuestContext {
            guest_vip: 7,
            guest_rip: 0x1400_1234,
            instruction_index: 3,
        }
    }

    #[test]
    fn windows_exception_codes_are_typed_without_losing_guest_context() {
        for (code, expected) in [
            (0xC000_0094, NativeGuestFaultKind::DivideError),
            (0xC000_001D, NativeGuestFaultKind::IllegalInstruction),
            (0xC000_0005, NativeGuestFaultKind::AccessViolation),
        ] {
            let NativeIsolatedResult::Fault(fault) = classify_native_exit(Some(code as i32), ctx())
            else {
                panic!("exception must be classified as a fault");
            };
            assert_eq!(fault.kind, expected);
            assert_eq!(fault.context, ctx());
            assert_eq!(fault.os_exception_code, Some(code));
        }
    }

    #[test]
    fn normal_helper_status_is_not_falsely_reported_as_hardware_fault() {
        assert_eq!(
            classify_native_exit(Some(5), ctx()),
            NativeIsolatedResult::Completed { exit_code: 5 }
        );
        assert_eq!(
            classify_native_exit(None, ctx()),
            NativeIsolatedResult::Fault(NativeGuestFault {
                kind: NativeGuestFaultKind::AbnormalTermination,
                context: ctx(),
                os_exception_code: None,
            })
        );
    }
}
