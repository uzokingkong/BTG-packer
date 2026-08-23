// ==============================================================================
// BTG Packer Test Payload — T1-1: C Basic (MinGW/MSVC/Clang 매트릭스용)
// ==============================================================================
// 목적: switch/indirect call / SSE2 / printf / exit 등 실제 컴파일러 코드 패턴을
//       커버하는 최소 C 페이로드. 컴파일러 없이 소스만 추가; 빌드는 build_matrix.ps1 이 담당.
//
// 컴파일 (MinGW 예):
//   gcc -O2 -o c_basic.exe c_basic.c
//   gcc -O0 -o c_basic_o0.exe c_basic.c
//   x86_64-w64-mingw32-gcc -O3 -o c_basic_o3.exe c_basic.c
// ==============================================================================
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 1) 기본 산술 + printf
static int fib(int n) {
    if (n <= 1) return n;
    return fib(n - 1) + fib(n - 2);
}

// 2) switch 문 (jump table 생성)
static const char* classify(int x) {
    switch (x % 8) {
        case 0: return "zero";
        case 1: return "one";
        case 2: return "two";
        case 3: return "three";
        case 4: return "four";
        case 5: return "five";
        case 6: return "six";
        case 7: return "seven";
        default: return "other";
    }
}

// 3) 함수 포인터 (indirect call)
typedef int (*op_fn)(int, int);
static int add_fn(int a, int b) { return a + b; }
static int mul_fn(int a, int b) { return a * b; }

static int apply(op_fn fn, int a, int b) {
    return fn(a, b);
}

// 4) 스택 할당 + memcpy
static unsigned long checksum(const int* arr, int n) {
    unsigned long s = 0;
    for (int i = 0; i < n; i++) s += (unsigned long)arr[i];
    return s;
}

int main(void) {
    // fib
    int f10 = fib(10);
    printf("fib(10) = %d\n", f10);
    if (f10 != 55) { fprintf(stderr, "FAIL: fib\n"); return 1; }

    // switch
    for (int i = 0; i < 8; i++) {
        printf("classify(%d) = %s\n", i, classify(i));
    }

    // indirect call
    op_fn ops[2] = { add_fn, mul_fn };
    int r0 = apply(ops[0], 3, 4);
    int r1 = apply(ops[1], 3, 4);
    printf("add(3,4)=%d mul(3,4)=%d\n", r0, r1);
    if (r0 != 7 || r1 != 12) { fprintf(stderr, "FAIL: indirect call\n"); return 1; }

    // checksum
    int arr[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    unsigned long s = checksum(arr, 8);
    printf("checksum = %lu\n", s);
    if (s != 36) { fprintf(stderr, "FAIL: checksum\n"); return 1; }

    printf("c_basic: ALL PASS\n");
    return 0;
}
