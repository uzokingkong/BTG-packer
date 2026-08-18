// ==============================================================================
// BTG Packer Test Payload — T1-1: SSE2 Intrinsics (컴파일러 매트릭스용)
// ==============================================================================
// 목적: SSE2/SSE4.1 벡터 연산이 포함된 코드 패턴. lifter의 MOVDQU/PADDQ/PCMPEQB 등을
//       실제 컴파일러 출력으로 검증한다.
//
// 컴파일 (MinGW):
//   gcc -O2 -msse4.1 -o c_sse.exe c_sse.c
// 컴파일 (MSVC):
//   cl /O2 /arch:SSE2 c_sse.c
// ==============================================================================
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <emmintrin.h>  // SSE2

// SSE2: 16바이트 XOR
static void xor16(const uint8_t* a, const uint8_t* b, uint8_t* out) {
    __m128i va = _mm_loadu_si128((const __m128i*)a);
    __m128i vb = _mm_loadu_si128((const __m128i*)b);
    __m128i vr = _mm_xor_si128(va, vb);
    _mm_storeu_si128((__m128i*)out, vr);
}

// SSE2: 16바이트 덧셈 (바이트 단위 포화)
static void adds16(const uint8_t* a, const uint8_t* b, uint8_t* out) {
    __m128i va = _mm_loadu_si128((const __m128i*)a);
    __m128i vb = _mm_loadu_si128((const __m128i*)b);
    __m128i vr = _mm_adds_epu8(va, vb);
    _mm_storeu_si128((__m128i*)out, vr);
}

// SSE2: memcmp (16바이트)
static int equal16(const uint8_t* a, const uint8_t* b) {
    __m128i va = _mm_loadu_si128((const __m128i*)a);
    __m128i vb = _mm_loadu_si128((const __m128i*)b);
    __m128i cmp = _mm_cmpeq_epi8(va, vb);
    int mask = _mm_movemask_epi8(cmp);
    return mask == 0xFFFF;
}

// 스칼라 fallback (XOR, 비교)
static void xor16_scalar(const uint8_t* a, const uint8_t* b, uint8_t* out) {
    for (int i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
}

int main(void) {
    uint8_t a[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                     0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint8_t b[16] = {0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,
                     0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00};

    uint8_t sse_out[16], ref_out[16];
    xor16(a, b, sse_out);
    xor16_scalar(a, b, ref_out);

    if (!equal16(sse_out, ref_out)) {
        fprintf(stderr, "FAIL: SSE2 xor16 != scalar\n");
        return 1;
    }
    printf("xor16: SSE2 == scalar OK\n");

    uint8_t c[16] = {200,200,200,200,200,200,200,200,
                     200,200,200,200,200,200,200,200};
    uint8_t d[16] = {100,100,100,100,100,100,100,100,
                     100,100,100,100,100,100,100,100};
    uint8_t sat_out[16];
    adds16(c, d, sat_out);
    // 200+100 = 300 > 255 -> saturate to 255
    for (int i = 0; i < 16; i++) {
        if (sat_out[i] != 255) {
            fprintf(stderr, "FAIL: adds_epu8 saturate at index %d: got %d\n", i, sat_out[i]);
            return 1;
        }
    }
    printf("adds_epu8 saturation: OK\n");
    printf("c_sse: ALL PASS\n");
    return 0;
}
