// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Security Framework
// ==============================================================================

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "btg-packer",
    author = "BTG Security Research Team",
    version = "1.0.0",
    about = "Bidirectional Trigger Graph (BTG) Security Framework"
)]
pub struct CliArgs {
    /// Input PE target binary path
    #[arg(short, long, default_value = "dummy_target.exe")]
    pub input: PathBuf,

    /// Output protected PE binary path
    #[arg(short, long, default_value = "protected_btg.exe")]
    pub output: PathBuf,

    /// P3-1: 결정적 빌드용 시드. `--seed <u64>`로 패킹의 모든 RNG
    /// (셔플/mba_constant/crypto 시드/폴리 시드/레이아웃 패드)를 고정한다.
    /// 같은 input + seed + config → 같은 output (재현·디버깅·상용 배포용).
    #[arg(long)]
    pub seed: Option<u64>,

    /// Obfuscation intensity level (1: Basic, 2: MBA, 3: Overlapping + MBA)
    #[arg(short = 'l', long, default_value_t = 3)]
    pub obf_level: u32,

    /// Enable Anti-Debugging features
    #[arg(short = 'a', long, default_value_t = false)]
    pub anti_debug: bool,

    /// Run Automated Multi-Compiler QA Benchmark Suite
    #[arg(short = 't', long, default_value_t = false)]
    pub test_qa: bool,

    /// P0-1: 실전 컴파일러 코퍼스를 생성하고 종료한다 (corpus/*.exe).
    /// test/ 크레이트를 -O0/-O1/-O2/-O3/LTO/CGU16/panic-abort/overflow-checks
    /// 프로파일로 각각 빌드해 QA가 패킹·실행 검증할 실제 PE 집합을 만든다.
    #[arg(long, default_value_t = false)]
    pub qa_gen_corpus: bool,

    /// Enable verbose Debug logging mode
    #[arg(short = 'd', long, default_value_t = false)]
    pub debug: bool,

    /// Output log file path (optional)
    #[arg(short = 'g', long)]
    pub log_file: Option<PathBuf>,

    /// Inject runtime block execution tracer into packed binary
    #[arg(long, default_value_t = false)]
    pub trace_blocks: bool,

    /// v3: Disable composite VM encryption (boot-stub RC4 code/string encryption).
    /// By default (flag absent) the real-encryption layer is ON.
    #[arg(long, default_value_t = false)]
    pub no_crypto: bool,

    /// v3-composite: virtualize the boot-stub RC4 key schedule (KSA) into the
    /// generated VM (bytecode + handlers). Requires the crypto layer.
    #[arg(long, default_value_t = false)]
    pub vm: bool,

    /// Run the VM self-test (lifter / interpreter / native handlers) and exit.
    #[arg(long, default_value_t = false)]
    pub vm_test: bool,

    /// v26 (M6): 원본 .text → VM lift 커버리지 진단. 패킹 없이 대상 PE의 원본
    /// `.text`를 기본 블록으로 디코드해 각 블록이 현재 1:1 리프터로 lift 가능한지
    /// 리포트를 출력하고 종료한다 (lift 불가 명령 나열 = A-5 진단).
    #[arg(long, default_value_t = false)]
    pub text_vm: bool,

    /// M6 Phase-2: 원본 .text의 EP로부터 도달 가능한 CFG 전체를 단일 VM 프로그램으로
    /// lift해 크기/블록수/커버리지를 리포트하고 종료한다. (OEP→VM entry 전환 데이터
    /// 경로 검증 — 패킹 없음)
    #[arg(long, default_value_t = false)]
    pub text_vm_oep: bool,

    /// v4: 암호화된 코드 영역을 실행 불가 데이터 섹션(.vdata)으로 옮긴다.
    /// 실행 가능 섹션(.textb)의 엔트로피를 크게 낮추고(거의 0에 가까운 0x00 스테이징),
    /// 부트 스텁이 로드 시 복사+복호화한다. 리소스/데이터 위장의 실질적 구현.
    #[arg(long, default_value_t = false)]
    pub payload_relocate: bool,

    /// v4: 재배치된 페이로드(.vdata)를 정식 RT_RCDATA 리소스로 등록한다
    /// (PE 리소스 디렉터리 재구성, --payload-relocate 필요).
    #[arg(long, default_value_t = false)]
    pub rsrc_register: bool,

    /// v4: 코드 영역 RC4 암호화 커버리지(%).
    /// 100 = 기존 동작(전체 암호화), 낮출수록 .textb 섹션 엔트로피가 낮아진다.
    /// 예: 40 → 코드 영역의 앞 40%만 암호화, 나머지는 CFG 평탄화된 평문 코드로 유지.
    #[arg(long, default_value_t = 100)]
    pub crypto_coverage: u32,

    /// v7: 청크 체이닝 RC4 (256B 청크, Key_i = 이전 청크 평문) + 자기파괴
    /// (복호화 후 시드/S-box/페이로드 원본 소거). 정적 RC4 키 추출 언패킹을
    /// 원천 차단한다. --vm의 KSA를 대체하며 --integrity와 정상 조합된다.
    #[arg(long, default_value_t = false)]
    pub chained_crypto: bool,

    /// v5: 부트 스텁이 복호화 직후 코드 영역 CRC32를 검증한다 (안티-패치).
    /// 파일의 암호화 바이트가 변조되면 복호화 결과가 깨져 CRC 불일치 → ud2 크래시.
    #[arg(long, default_value_t = false)]
    pub integrity: bool,

    /// v6: 임포트 테이블 은닉 — 원본 import 이름/디렉터리를 제거하고
    /// kernel32!LoadLibraryA/GetProcAddress 더미 import만 남긴 뒤, 부트 스텁이
    /// 실행 시점에 나머지 API를 해석해 원본 IAT 슬롯을 채운다.
    #[arg(long, default_value_t = false)]
    pub iat_hide: bool,

    /// v6: 메모리 하드닝 — 복호화 직후 ntdll!NtProtectVirtualMemory로
    /// .textb를 RWX→RX(PAGE_EXECUTE_READ) 전환 (덤프 후 패치 차단).
    /// 해석 실패 시 보호 없이 계속 실행(fail-open).
    #[arg(long, default_value_t = false)]
    pub mem_harden: bool,

    /// v8: 디스패처 연동 '실행 후 재암호화' (Phase 0.3, T3 덤프 저항).
    /// 모든 블록을 블록별 MBA 키로 개별 RC4 암호화해 파일에 저장하고,
    /// 디스패처가 매 디스패치마다 (1) 직전 블록을 즉시 재암호화하고
    /// (2) 타깃 블록을 복호화한 뒤 점프한다. 어느 순간에도 실행 중인
    /// 블록만 평문이므로, 실행 중간 덤프는 대부분 암호문 상태가 되어
    /// 원본 재구성이 불가능해진다. 부트 스텁의 영역 일괄 복호화는 생략된다.
    /// (--integrity와 조합 시 암호문/파일 상태 CRC 검증, --chained-crypto보다 우선)
    #[arg(long, default_value_t = false)]
    pub dispatcher_reencrypt: bool,

    /// v9: FULL — 최대 보호 스택을 한 번에 켠다.
    /// `-l 3 -a --dispatcher-reencrypt --integrity --payload-relocate
    ///  --rsrc-register --iat-hide --mem-harden` 과 동등 (crypto 강제).
    /// 개별 플래그와 함께 쓰면 각 플래그가 우선하고, 상충 조합은 기존
    /// 규칙(재암호화 우선 등)으로 해소된다.
    #[arg(long, default_value_t = false)]
    pub full: bool,

    /// M6 Phase-2: OEP→VM entry 전환 — 부트 스텁이 원본 .text를 평문 복호화하지 않고
    /// lift된 프로그램 VM 모듈로 디스패치하게 한다. (`--vm` 필요) 회귀 안전을 위해
    /// 기본 경로(`--full`/`--vm`)는 이 플래그 없이 기존 동작을 유지한다.
    #[arg(long, default_value_t = false)]
    pub vm_oep: bool,

    /// P3 (G1): --vm-oep의 프로그램 가상화 백엔드를 상용 엔진(risc→poly→threaded)으로
    /// 전환한다. `--vm --vm-oep --vm-commercial` 모두 주어야 상용 경로를 쓰고,
    /// 레거시 1:1 VM(--vm-oep 단독)은 바이트 동일하게 유지된다. (회귀 안전 토글)
    #[arg(long, default_value_t = false)]
    pub vm_commercial: bool,

    /// M7: on-demand 재암호화(anti-dump) — 원본 .text/.data/.rdata 런을 파일에는
    /// 암호문으로 저장하고 실행 중 on-demand로만 복호화→사용→재암호화해, 덤프 시
    /// 평문이 노출되지 않게 한다. (기본 false → 기존 경로 유지)
    #[arg(long, default_value_t = false)]
    pub m7: bool,

    /// M8: VM 핸들러 테이블 MBA 난독화 — VM의 handler 테이블 항목(절대 주소)을
    /// `K = a + b`(mod 2^64)로 XOR 암호화하고, 디스패처가 MBA 항등식
    /// `a+b == (a^b)+2*(a&b)`로 런타임에 K를 유도해 복호화한다. 덤프된 handler
    /// 테이블에서 주소가 직접 읽히지 않게 한다. (기본 false → 기존 경로 유지)
    #[arg(long, default_value_t = false)]
    pub m8: bool,

    /// M8: VM 성능 벤치마크 — 인터프리터 vs 네이티브 VM 처리량을 측정해 출력하고
    /// 종료한다. (패킹 없음)
    #[arg(long, default_value_t = false)]
    pub vm_bench: bool,

    /// v42 (M9): VM 바이트코드 매퍼 — 패킹 시 lift 되는 모든 원본 명령의
    /// `바이트코드 오프셋 → 원본 VA/디스어셈블리` 매핑을 `<output>.map` 파일로
    /// 기록한다. 패킹 후 바이너리가 VM 내부에서 크래시할 때, 덤프의 faulting
    /// 오프셋을 원본 명령으로 역추적하는 데 쓴다. (기본 false → 기존 동작 유지)
    #[arg(long, default_value_t = false)]
    pub map: bool,

    /// v50 (M10): 블록 단위 심볼릭 맵 — `--map`의 명령 단위 기록에 더해 lift된
    /// 기본 블록 경계(바이트코드 오프셋 범위 ↔ 원본 블록 VA 범위)와 `.pdata`
    /// 함수 귀속을 `<output>.sym` 파일로 기록한다. 크래시 faulting 오프셋을
    /// 원본 블록/함수/명령으로 가역적으로 역추적하는 데 쓴다. (`--map`도 함께 켠다)
    #[arg(long, default_value_t = false)]
    pub sym_map: bool,

    /// 원본 `.pdata` SEH 테이블을 바이트 단위로 그대로 둔다. 기본값은 원본
    /// RUNTIME_FUNCTION 항목을 모두 보존하면서 새 디스패처 부트 leaf를 추가한다.
    /// 이 플래그는 해당 leaf 추가도 건너뛰는 진단/호환 모드다.
    #[arg(long, default_value_t = false)]
    pub keep_pdata: bool,

    /// v13.4d diag: 디스패처에 "마지막 32개 dispatched logical block id" ring-buffer 를
    /// 주입한다 (표준 디스패처 경로에서만; 재암호화 디스패처는 미지원 — 경고 후 무시).
    /// 실행 중 매 디스패치마다 target block id 를 .btg 섹션 테이블 앞 예약 영역에
    /// 기록한다. 종료 시점 once.rs:166 패닉 직전에 dispatcher 가 어느 블록들로
    /// 되돌아갔는지 덤프(cdb/winDbg)에서 읽어 좁히는 데 쓴다.
    #[arg(long, default_value_t = false)]
    pub block_ring: bool,

    /// v62 (기본): BTG-C1 커스텀 512-bit 스트림 사이퍼를 기본 암호로 사용한다.
    /// (plan.txt 4~6단계 완료 — 벌크/스테이트풀 per-block/재암호화/VM 경로 배선.
    ///  이 플래그는 이제 기본값이므로 명시적으로만 의미가 있고, 해제는 --rc4.)
    #[arg(long, default_value_t = false)]
    pub custom_cipher: bool,

    /// v62: RC4-256으로 되돌린다 (--custom-cipher 해제). C1 비호환 경로
    /// (chained/--vm-oep)의 폴백/디버그/테스트용 — 기본은 BTG-C1.
    #[arg(long, default_value_t = false)]
    pub rc4: bool,

    /// v63 (T3-1 Phase B): crypto primitive 선택 — `rc4` | `c1` | `chacha20`.
    /// `chacha20` = ChaCha20 (RFC 8439) 스트림 — 코드/문자열 영역 at-rest 암호화를
    /// 검증된 현대 암호로 전환 (평문 bulk 경로 전용; chained/reencrypt/--vm/--vm-oep
    /// 조합에서는 폴백). 지정 시 `--rc4`/`--custom-cipher`보다 우선한다.
    #[arg(long, value_enum)]
    pub crypto_mode: Option<CryptoModeCli>,
}

/// v63: `--crypto-mode` 선택지.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoModeCli {
    /// RC4-256 (레거시).
    #[value(name = "rc4")]
    Rc4,
    /// BTG-C1 커스텀 512-bit 스트림 사이퍼 (기본).
    #[value(name = "c1")]
    C1,
    /// ChaCha20 (RFC 8439) — T3-1.
    #[value(name = "chacha20")]
    ChaCha20,
}
