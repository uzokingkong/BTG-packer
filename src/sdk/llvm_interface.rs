// ==============================================================================
// BTG - Commercial-Grade VM: LLVM IR & Compiler Ingestion Interface
// ==============================================================================
// LLVM 컴파일러 패스(Clang/Rustc)로부터 방출된 구조화된 가상화 메타데이터/IR
// 파싱 및 RiscProgram 직접 합성 인터페이스.
// ==============================================================================

use crate::vm::risc::{MicroInstr, MicroOperand, RiscOp, RiscProgram};
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct LlvmVirtualFunction {
    pub name: String,
    pub body: Vec<MicroInstr>,
}

pub struct LlvmIngestionInterface;

impl LlvmIngestionInterface {
    /// LLVM 패스로부터 전달받은 원시 연산 리스트를 RiscProgram으로 직접 변환
    pub fn build_risc_program(vf: &LlvmVirtualFunction) -> RiscProgram {
        RiscProgram::new(vf.body.clone())
    }
}
