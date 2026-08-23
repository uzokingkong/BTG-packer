// ==============================================================================
// BTG Packer Test Payload — T1-1: C++ SEH (__try/__except)
// ==============================================================================
// 목적: Win64 SEH(__try/__except) 예외 처리 경로 검증.
//       패킹 후 SEH 핸들러가 정상 실행되어야 한다.
//       (.pdata/UNWIND_INFO 일관성이 깨지면 접근 위반이 unhandled가 됨)
//
// 컴파일 (MSVC):
//   cl /O2 /EHa cpp_seh.cpp
// 컴파일 (MinGW — SEH는 별도 플래그):
//   gcc -O2 -o cpp_seh.exe cpp_seh.c -lmsvcrt   (MSVC CRT SEH 사용)
// ==============================================================================
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// Test 1: NULL 포인터 접근 -> EXCEPTION_ACCESS_VIOLATION -> 핸들러가 잡음
static int test_av_handled(void) {
    volatile int* p = NULL;
    int caught = 0;
    __try {
        int v = *p;  // ACCESS_VIOLATION
        (void)v;
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION
                ? EXCEPTION_EXECUTE_HANDLER
                : EXCEPTION_CONTINUE_SEARCH) {
        caught = 1;
    }
    return caught;
}

// Test 2: 정수 0 나누기 -> EXCEPTION_INT_DIVIDE_BY_ZERO
static int test_div0_handled(void) {
    volatile int x = 42, y = 0;
    int caught = 0;
    __try {
        int r = x / y;
        (void)r;
    } __except (GetExceptionCode() == EXCEPTION_INT_DIVIDE_BY_ZERO
                ? EXCEPTION_EXECUTE_HANDLER
                : EXCEPTION_CONTINUE_SEARCH) {
        caught = 1;
    }
    return caught;
}

// Test 3: 중첩 __try/__except
static int test_nested_seh(void) {
    volatile int* null_ptr = NULL;
    int outer = 0, inner = 0;
    __try {
        __try {
            *null_ptr = 5;  // AV
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            inner = 1;
            // inner는 잡았으므로 outer로 전파 안 됨
        }
        outer = 1;  // 이쪽으로 실행 계속
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        outer = -1; // 여기 오면 안 됨
    }
    return (inner == 1 && outer == 1) ? 1 : 0;
}

// Test 4: __finally 블록 실행
static int g_finally_ran = 0;
static int test_finally(void) {
    volatile int* p = NULL;
    __try {
        *p = 1;  // AV
    } __finally {
        g_finally_ran = 1;  // 예외 발생해도 반드시 실행
    }
    return 0;  // 여기까지 오면 실패 (예외 미처리)
}

static int test_finally_wrapper(void) {
    g_finally_ran = 0;
    int caught = 0;
    __try {
        test_finally();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        caught = 1;
    }
    return (caught == 1 && g_finally_ran == 1) ? 1 : 0;
}

int main(void) {
    printf("SEH Test 1 (AV handled): ");
    if (!test_av_handled()) { printf("FAIL\n"); return 1; }
    printf("PASS\n");

    printf("SEH Test 2 (div-by-zero): ");
    if (!test_div0_handled()) { printf("FAIL\n"); return 1; }
    printf("PASS\n");

    printf("SEH Test 3 (nested SEH): ");
    if (!test_nested_seh()) { printf("FAIL\n"); return 1; }
    printf("PASS\n");

    printf("SEH Test 4 (__finally): ");
    if (!test_finally_wrapper()) { printf("FAIL\n"); return 1; }
    printf("PASS\n");

    printf("cpp_seh: ALL PASS\n");
    return 0;
}
