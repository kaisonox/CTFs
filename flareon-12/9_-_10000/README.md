# 10000

## Overview
The `license.bin` file contains 34,000 bytes divided into 10,000 parts, each 34 bytes with the following structure:

```cpp
struct LicenseData {
    WORD rc_id;
    BYTE data[32];
}
```

Each part's data is validated by a `check` function present in each of the 10,000 DLLs.

## Solution Process

### Step 1: Extract DLLs
Run `dump_rcdata.exe` to extract DLLs from `license.bin`.

### Step 2: Analyze Check Functions
Each `check` function follows the same pattern:
- Series of `f....()` functions to transform data
- Ends with matrix exponentiation
- Result is compared with target value

The `rc_id` order must also be correct.

### Step 3: Build Tools
- `build_f_function_database.py` - Extract function types and constants from `f....()` functions
- `dump_check_calls.py` - List `f....()` functions and related constants within `check()` functions
- `build_license.py` - Generate valid `license.bin`

## Result
The correct input sequence: `4498291314891210521449296`