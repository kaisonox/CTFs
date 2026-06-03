# FlareAuthenticator

## Overview
This program uses obfuscated `jmp rax` and `call rax` instructions. The solution involves writing scripts to search and resolve these instructions, then patching them with specific addresses.

## Authentication Logic
When a key is pressed, the program calculates:

```cpp
round_result = obf_transform(ctx, index) * obf_transform(ctx, (index << 8) | (0x30 + digit));
accumulator += round_result;
```

Where `obf_transform` is located at RVA 0x80760.

After 25 inputs, if `accumulator == target (0x0BC42D5779FEC401)`, the input is considered correct.

## Data Structures

```cpp
struct PtrVector {
    void **begin;
    void **end;
    void **cap;
};

struct CharPtrVector {
    const char **begin;
    const char **end;
    const char **cap;
};

struct FlareAuthContext {
    unsigned __int8 _pad0[48];
    PtrVector cells;
    QWidget *ok_button;
    QWidget *delete_button;
    CharPtrVector input_digits;
    uint64_t _reserved0;
    uint64_t accumulator;
};
```

## Solution Steps
1. Write script to fuzz `obf_transform` with all possible values of `value` and `index`
2. Save results to `obf_transform_test_results.txt`
3. Write script to find the correct input sequence

## Result
Correct input sequence: `4498291314891210521449296`