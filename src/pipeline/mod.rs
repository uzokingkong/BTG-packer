// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Pipeline Context & Module Declarations
// ==============================================================================

pub mod build;
pub mod pass1_slice;
pub mod pass2_shuffle;
pub mod pass3_encode;
pub mod pass4_section;
pub mod patch_data;
pub mod crypto;
pub mod iat_hide;
pub mod pack;
pub mod ondemand;
pub mod poly_embed;
pub mod rsrc_register;
pub mod selective_vm;
pub mod validate;

use crate::graph::{BasicBlock, ShuffledLayout};
use crate::core::trigger_block::TriggerBlock;
use crate::pe::{parser::TargetPeInfo, builder::SectionData};
use std::collections::BTreeMap;

/// 각 Pass 사이에 공유되는 파이프라인 상태.
///
/// `main`에서 `PipelineContext`를 생성하고 각 Pass 함수에 `&mut self`로 전달한다.
/// 각 Pass는 이전 Pass의 결과를 소비하거나 참조하여 다음 단계 출력을 채운다.
pub struct PipelineContext {
    // ── 입력 (파이프라인 시작 전 설정) ──────────────────────────────────────────
    pub target_info: TargetPeInfo,
    pub dispatcher_va: u64,
    pub dispatcher_rva: u32,
    pub obf_complexity: usize,

    // ── Pass 1 출력 ─────────────────────────────────────────────────────────────
    /// CfgExtractor가 추출한 원본 기본 블록 목록
    pub basic_blocks: Vec<BasicBlock>,
    /// MicroSlicer가 생성한 Trigger Block 목록
    pub trigger_blocks: Vec<TriggerBlock>,
    /// 원본 `.text` VA → Trigger Block ID 매핑 (정렬 BTreeMap)
    pub va_to_trigger_id: BTreeMap<u64, u32>,

    // ── Pass 2 출력 ─────────────────────────────────────────────────────────────
    /// 물리 레이아웃 셔플 결과
    pub shuffled_layout: Option<ShuffledLayout>,
    /// 점프 테이블 시작 오프셋 (dispatcher_va 기준 섹션 내 byte offset)
    pub table_offset: usize,
    /// 첫 번째 코드 블록의 시작 오프셋
    pub first_block_offset: usize,

    // ── Pass 4 출력 ─────────────────────────────────────────────────────────────
    /// 완성된 .btg 섹션 데이터
    pub btg_section_data: Option<SectionData>,

    // ── Patch 출력 ──────────────────────────────────────────────────────────────
    /// 재배치·패치된 섹션 목록 (.text, .rdata, .data, .pdata 등)
    pub patched_sections: Vec<SectionData>,

    // ── v3 Crypto 출력 ─────────────────────────────────────────────────────────
    /// 암호화 부트 스텁의 섹션 내 오프셋 (0이면 섹션 시작점 = OEP)
    pub boot_entry_offset: u32,
    /// 암호화 적용 여부
    pub crypto_enabled: bool,
    /// v4: --payload-relocate 시 암호화된 코드 페이로드를 담는 데이터 섹션
    pub payload_section_data: Option<SectionData>,
    /// 페이로드 섹션 RVA (rsrc_register가 리소스 데이터 엔트리로 사용)
    pub payload_rva: u32,
    /// 페이로드 길이
    pub payload_len: u32,
    /// --rsrc-register: 재구성된 리소스 디렉터리 RVA/크기 (0 = 미사용)
    pub rsrc_dir_rva: u32,
    pub rsrc_dir_size: u32,
    /// entry 블록 ID / 시드 (boot stub이 dispatcher 진입 시 push; 디스패처가
    /// MBA 항등식으로 키를 재도출한다)
    pub entry_block_id: usize,
    pub entry_seed: u32,
    /// v5: 안티디버그 부트 스텁 사용 여부 (validate EP 프롤로그 검사용)
    pub anti_debug: bool,
    /// v6: MBA 키 스케줄 상수 (패킹당 1회 랜덤 — 슬라이서/패스3/패스4/디스패처 공유)
    pub mba_constant: u32,
    // ── v6: IAT 은닉 + 메모리 하드닝 ──────────────────────────────────────────
    /// --iat-hide 사용 여부 (원본 import 제거 + 더미 import)
    pub iat_hide: bool,
    /// --mem-harden 사용 여부 (복호화 후 .textb RWX->RX)
    pub mem_harden: bool,
    /// v8: --dispatcher-reencrypt (Phase 0.3) — 블록별 개별 암호화 + 디스패처
    /// '실행 후 재암호화'. 블록 스텁 3-푸시 규약 / 길이 테이블 / 부트 스텁 생략을 결정.
    pub reencrypt: bool,
    /// M6 Phase-2: --vm-oep — 부트 스텁이 원본 .text를 평문 복호화하지 않고
    /// lift된 프로그램 VM 모듈로 디스패치. (기본 false → 기존 경로 유지)
    pub vm_oep: bool,
    /// M7: --m7 — on-demand 재암호화(anti-dump) 활성화 (기본 false → 기존 경로 유지)
    pub m7: bool,
    /// M8: --m8 — VM handler 테이블 MBA 난독화 (기본 false → 기존 경로 유지)
    pub m8: bool,
    /// v11: 직접 `call` 대상 블록 ID 집합 (재암호화 모드에서 평문 유지).
    /// call은 디스패처를 거치지 않고 블록을 직접 실행하므로, 암호문 상태로
    /// 남으면 0xC0000096 (privileged instruction) 크래시가 발생한다.
    pub call_target_block_ids: std::collections::HashSet<u32>,
    /// 원본 import 목록 (main에서 collect_from_pe로 채움)
    pub original_imports: Vec<crate::pipeline::iat_hide::OriginalImport>,
    /// 더미 import 디렉터리 RVA/크기 (build.rs가 DataDirectory[1]에 기록)
    pub iat_dir_rva: u32,
    pub iat_dir_size: u32,
    /// 더미 import IAT 슬롯 RVA (LoadLibraryA / GetProcAddress)
    pub iat_ll_slot_rva: u32,
    pub iat_gpa_slot_rva: u32,
    /// 리졸브 테이블 RVA/크기 (부트 스텁이 처리)
    pub iat_table_rva: u32,
    pub iat_table_len: u32,
    /// mem-harden 문자열 VA
    pub mem_ntdll_name_va: u64,
    pub mem_ntprot_name_va: u64,
    /// --keep-pdata — 원본 .pdata를 바이트 단위로 유지한다. 기본 모드도 모든 원본
    /// 항목을 보존하지만 디스패처 부트 leaf를 하나 추가한다.
    pub keep_pdata: bool,
    /// v13.4d diag: --block-ring — 표준 디스패처에 마지막 32개 logical block id
    /// ring-buffer 를 주입한다 (재암호화 디스패처는 미지원).
    pub block_ring: bool,
    /// v59: --custom-cipher — BTG-C1 커스텀 512-bit 스트림 사이퍼 사용 (기본 RC4).
    pub custom_cipher: bool,
    /// T1-1: 폴리모픽 VM 시드 (빌드마다 OsRng로 생성).
    pub poly_vm_seed: u64,
    /// T1-1: 폴리모픽 VM 시드 마스킹 분할 저장 값.
    pub poly_vm_seed_masked: u64,
    /// T1-3: SDK 마커 리전 lift 결과(폴리모픽 바이트코드+시드+오프셋). embed 단계가 소비.
    pub poly_vm_regions: Vec<crate::pipeline::selective_vm::PolyVmRegion>,
    /// T1-2: 리프트 불가로 거부된 리전 수.
    pub poly_vm_regions_rejected: usize,
    /// T1-3: 임베드된 `.btgvm` 섹션 (VM 진입 스텁 + 핸들러 테이블 + 폴리 바이트코드 + 시드).
    pub poly_vm_section: Option<crate::pe::builder::SectionData>,
    /// T1-3: 임베드된 VM 진입 스텁의 절대 VA (마커 트램펄린이 점프할 대상).
    pub poly_vm_entry_va: u64,
}

impl PipelineContext {
    pub fn new(
        target_info: TargetPeInfo,
        dispatcher_va: u64,
        dispatcher_rva: u32,
        obf_complexity: usize,
    ) -> Self {
        Self {
            target_info,
            dispatcher_va,
            dispatcher_rva,
            obf_complexity,
            basic_blocks: Vec::new(),
            trigger_blocks: Vec::new(),
            va_to_trigger_id: BTreeMap::new(),
            shuffled_layout: None,
            table_offset: 0,
            first_block_offset: 0,
            btg_section_data: None,
            patched_sections: Vec::new(),
            boot_entry_offset: 0,
            crypto_enabled: false,
            payload_section_data: None,
            payload_rva: 0,
            payload_len: 0,
            rsrc_dir_rva: 0,
            rsrc_dir_size: 0,
            entry_block_id: 0,
            entry_seed: 0,
            anti_debug: false,
            mba_constant: 0,
            iat_hide: false,
            mem_harden: false,
            reencrypt: false,
            vm_oep: false,
            m7: false,
            m8: false,
            call_target_block_ids: std::collections::HashSet::new(),
            original_imports: Vec::new(),
            iat_dir_rva: 0,
            iat_dir_size: 0,
            iat_ll_slot_rva: 0,
            iat_gpa_slot_rva: 0,
            iat_table_rva: 0,
            iat_table_len: 0,
            mem_ntdll_name_va: 0,
            mem_ntprot_name_va: 0,
            keep_pdata: false,
            block_ring: false,
            custom_cipher: false,
            poly_vm_seed: 0,
            poly_vm_seed_masked: 0,
            poly_vm_regions: Vec::new(),
            poly_vm_regions_rejected: 0,
            poly_vm_section: None,
            poly_vm_entry_va: 0,
        }
    }

    /// Pass 2 이후 확정된 `ShuffledLayout` 참조 반환.
    pub fn layout(&self) -> anyhow::Result<&ShuffledLayout> {
        self.shuffled_layout
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ShuffledLayout not yet built (Pass 2 not run)"))
    }

    /// Pass 2 이후 확정된 `ShuffledLayout` 가변 참조 반환.
    pub fn layout_mut(&mut self) -> anyhow::Result<&mut ShuffledLayout> {
        self.shuffled_layout
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("ShuffledLayout not yet built (Pass 2 not run)"))
    }

    /// `.text` 섹션의 VA 범위 (start, end).
    pub fn text_va_range(&self) -> (u64, u64) {
        let start = self.target_info.image_base + self.target_info.text_rva as u64;
        let end = start + self.target_info.text_vsize as u64;
        (start, end)
    }
}
