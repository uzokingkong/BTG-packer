// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Dispatcher shellcode validation
// ==============================================================================

use iced_x86::{Code, Decoder, DecoderOptions};

/// 디스패처 바이트열의 유효성 검증.
pub fn validate_dispatcher(bytes: &[u8]) -> crate::error::Result<()> {
    if bytes.is_empty() {
        return Err(anyhow::anyhow!("Dispatcher bytes are empty.").into());
    }

    let mut decoder = Decoder::with_ip(64, bytes, 0x2000, DecoderOptions::NONE);
    let mut valid_insts = 0;
    let mut found_ret_or_jmp = false;

    while decoder.can_decode() {
        let inst = decoder.decode();
        if inst.is_invalid() {
            return Err(anyhow::anyhow!("Found invalid instruction during dispatcher validation.").into());
        }
        valid_insts += 1;
        if inst.code() == Code::Retnq || inst.code() == Code::Jmp_rm64 {
            found_ret_or_jmp = true;
        }
    }

    if valid_insts == 0 {
        return Err(anyhow::anyhow!("No valid instructions decoded in dispatcher.").into());
    }
    if !found_ret_or_jmp {
        return Err(anyhow::anyhow!("Dispatcher does not contain ret or jmp instruction!").into());
    }

    Ok(())
}

