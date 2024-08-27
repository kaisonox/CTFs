
# PUSH Window, POP Nothing

## KMACTF.exe

Bài này cho file `KMACTF.exe`.

Chạy thử chương trình, ta thấy một edit box để nhập dữ liệu.

Nhập đúng dữ liệu, chương trình sẽ hiện messagebox "Correct", và thoát.

Nhập sai dữ liệu, chương trình sẽ hiện messagebox "Wrong", sau đó bắt đầu troll người chơi, cho xuất hiện ảnh động, đẩy các cửa sổ ra khỏi màn hình.


File `KMACTF.exe` giấu một file exe khác trong resource (id 130, type "BIN"), tạm gọi là `BIN_130`.

`BIN_130` được load từ resource, lưu vào `%TEMP%\Windows Update Checker 2.exe` và chạy.

`KMACTF.exe` và `Windows Update Checker 2.exe` giao tiếp với nhau qua pipe `\\.\pipe\KMACTF`.

Dữ liệu gửi qua pipe có dạng:

```
<command> <data>
```

Với `<command>` có độ dài 1 byte, `<data>` là một chuỗi hoặc số.

Các command:
1. `1` - Gửi chuỗi `<data>` qua pipe.
2. `5` - Gửi số (4 bytes) `<data>` qua pipe.
3. `8` - Gửi số (1 byte) `<data>` qua pipe.
4. `0x54` - ExitProcess.
5. `0x55` - Gọi hàm destroy (sẽ nói sau), sau đó ExitProcess.

`KMACTF.exe` có một edit box để nhập dữ liệu, sau đó gửi qua pipe.

```cpp
__int64 __fastcall handle_input(HWND a1)
{
  HWND DlgItem; // rax
  unsigned __int64 len_input; // [rsp+20h] [rbp-248h]
  _BYTE *command; // [rsp+28h] [rbp-240h]
  __int16 input[256]; // [rsp+50h] [rbp-218h] BYREF

  DlgItem = GetDlgItem(a1, 102);
  GetWindowTextW(DlgItem, (LPWSTR)input, 256);
  len_input = -1i64;
  do
    ++len_input;
  while ( input[len_input] );
  if ( len_input < 46 )
  {
    MessageBoxW(a1, L"Khong du dai", L"Khong du dai", 0);
    command = operator new(1ui64);
    *command = 0x55;
    write_read_pipe(command, 1i64);
    ExitProcess(0);
  }
  write_read_pipe_command_1((const WCHAR *)input);
  return ((__int64 (*)(void))communicate)();
}
```

Chuỗi nhập vào phải có độ dài ít nhất 46 ký tự, nếu không sẽ báo lỗi và gửi lệnh `0x55` qua pipe.

Gọi hàm `write_read_pipe_command_1` để gửi chuỗi qua pipe.

Sau đó, gọi hàm `communicate`, tiếp tục giao tiếp với `Windows Update Checker 2.exe`.

```cpp
void __noreturn communicate()
{
  __int64 v0; // rdx
  _BYTE *command; // [rsp+28h] [rbp-30h]

  while ( 1 )
  {
    command = operator new(1ui64);
    *command = 8;
    write_read_pipe(command, 1u);
    switch ( *command )
    {
      case 0x2B:
        BUG_caller();
      case 0x2F:
      case 0x43:
      case 0x44:
      case 0x46:
      case 0x4E:
      case 0x50:
      case 0x63:
      case 0x6A:
      case 0x6B:
      case 0x70:
      case 0x71:
      case 0x74:
      case 0x77:
        debug_break();
        break;
      case 0x30:
      case 0x36:
      case 0x37:
      case 0x41:
      case 0x42:
      case 0x4B:
      case 0x4C:
      case 0x4F:
      case 0x54:
      case 0x62:
      case 0x67:
      case 0x79:
      case 0x7A:
        read_addr_0();
        break;
      case 0x31:
      case 0x34:
      case 0x35:
      case 0x38:
      case 0x3D:
      case 0x49:
      case 0x4A:
      case 0x55:
      case 0x57:
      case 0x64:
      case 0x66:
      case 0x72:
      case 0x75:
        read_cr0();
        break;
      case 0x32:
        BUG_caller();
      case 0x33:
      case 0x39:
      case 0x45:
      case 0x47:
      case 0x4D:
      case 0x51:
      case 0x53:
      case 0x56:
      case 0x59:
      case 0x65:
      case 0x68:
      case 0x69:
      case 0x6E:
        error_div_by_zero(0x140000000i64, v0);
        break;
      case 0x48:
        BUG_caller();
      case 0x52:
        BUG_caller();
      case 0x58:
        BUG_caller();
      case 0x5A:
        BUG_caller();
      case 0x61:
        BUG_caller();
      case 0x6C:
        BUG_caller();
      case 0x6D:
        BUG_caller();
      case 0x6F:
        BUG_caller();
      case 0x73:
        BUG_caller();
      case 0x76:
        BUG_caller();
      case 0x78:
        BUG_caller();
      case 0xCC:
        *command = 0x54;
        write_read_pipe(command, 1u);
        ExitProcess(0);
      default:
        break;
    }
    j_j_free(command);
  }
}
```

`communicate` gọi hàm `write_read_pipe` với lệnh `0x8`, dữ liệu nhận về là một byte, sau đó xử lý theo các case.

Các case này đều gọi những hàm mà sẽ tạo ra lỗi, trừ case `0xCC` sẽ gửi lệnh `0x54` qua pipe và thoát chương trình.
- `BUG_caller`: lỗi `STATUS_ILLEGAL_INSTRUCTION`
- `debug_break`: lỗi `STATUS_BREAKPOINT`
- `read_addr_0`: lỗi `STATUS_ACCESS_VIOLATION`
- `read_cr0`: lỗi `STATUS_PRIVILEGED_INSTRUCTION`
- `error_div_by_zero`: lỗi `STATUS_INTEGER_DIVIDE_BY_ZERO`

Trước đó, trong hàm `WndProc` của `KMACTF.exe`, tác giả đã đăng ký một exception handler để xử lý các lỗi này.

```cpp
LRESULT __fastcall wnp_proc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  struct _LIST_ENTRY *RtlAddVectoredExceptionHandler; // [rsp+40h] [rbp-88h]
  struct tagPAINTSTRUCT Paint; // [rsp+60h] [rbp-68h] BYREF

  switch ( uMsg )
  {
    case WM_DESTROY:
      PostQuitMessage(0);
      ExitProcess(0);
    case WM_PAINT:
      BeginPaint(hWnd, &Paint);
      RtlAddVectoredExceptionHandler = setup(0xFDE7F515, 0xF9D7E6D5);
      ((void (__fastcall *)(__int64, __int64 (__fastcall *)(__int64)))RtlAddVectoredExceptionHandler)(
        1i64,
        write_read_pipe_command_5);
      EndPaint(hWnd, &Paint);
      break;
    case WM_COMMAND:
      switch ( (unsigned __int16)wParam )
      {
        case 'g':
          handle_input(hWnd);
          break;
        case 'h':
          DialogBoxParamW(hInstance, (LPCWSTR)0x67, hWnd, (DLGPROC)DialogFunc, 0i64);
          break;
        case 'i':
          CloseHandle(hObject);
          DestroyWindow(hWnd);
          break;
        default:
          return DefWindowProcW(hWnd, uMsg, wParam, lParam);
      }
      break;
    default:
      return DefWindowProcW(hWnd, uMsg, wParam, lParam);
  }
  return 0i64;
}
```

Hàm `setup` sẽ duyệt qua các module, tìm module có custom_hash `0xFDE7F515`, sau đó duyệt các hàm của module đó, tìm hàm có custom_hash `0xF9D7E6D5`. Hàm trả về chính là hàm `AddVectoredExceptionHandler`.

(Ngoài ra `setup` còn thực hiện load file `BIN_130` từ resource, lưu vào `%TEMP%\Windows Update Checker 2.exe` và chạy).

`AddVectoredExceptionHandler` thêm `write_read_pipe_command_5` vào vectored exception handler.

`write_read_pipe_command_5` sẽ gửi lệnh `0x5`, kèm mã lỗi exception, qua pipe.


## Windows Update Checker 2.exe

Hàm xử lý chính của `Windows Update Checker 2.exe`:

```cpp
void __noreturn communicate()
{
  char v0; // [rsp+40h] [rbp-B8h]
  char v1; // [rsp+41h] [rbp-B7h]
  int m; // [rsp+44h] [rbp-B4h]
  int error_code; // [rsp+48h] [rbp-B0h]
  int k; // [rsp+4Ch] [rbp-ACh]
  int n; // [rsp+50h] [rbp-A8h]
  int i; // [rsp+58h] [rbp-A0h]
  int ii; // [rsp+5Ch] [rbp-9Ch]
  HANDLE hNamedPipe; // [rsp+68h] [rbp-90h]
  int j; // [rsp+70h] [rbp-88h]
  unsigned __int64 v10; // [rsp+78h] [rbp-80h]
  unsigned __int64 len_data; // [rsp+80h] [rbp-78h]
  __int64 v12; // [rsp+88h] [rbp-70h]
  DWORD NumberOfBytesWritten; // [rsp+C8h] [rbp-30h] BYREF
  DWORD NumberOfBytesRead; // [rsp+CCh] [rbp-2Ch] BYREF

  while ( 1 )
  {
    hNamedPipe = CreateNamedPipeW(L"\\\\.\\pipe\\KMACTF", 3u, 6u, 1u, 0x6000u, 0x6000u, 0, 0i64);
    if ( ConnectNamedPipe(hNamedPipe, 0i64) || GetLastError() == 535 )
    {
      memset((void *)lpBuffer, 0, 0x600ui64);
      ReadFile(hNamedPipe, (LPVOID)lpBuffer, 0x600u, &NumberOfBytesRead, 0i64);
      switch ( *(_BYTE *)lpBuffer )
      {
        case 5:
          error_code = *(_DWORD *)((char *)lpBuffer + 1);
          if ( expected_error_code[curr_idx] != error_code )
            checking_done = 0;
          v0 = *(_BYTE *)(base64_encoded + curr_idx);
          if ( error_code == (unsigned int)STATUS_BREAKPOINT )
          {
            dword_140005880[curr_idx] = STATUS_BREAKPOINT;
            for ( i = 0; i < 10; ++i )
              *(_BYTE *)(base64_encoded + curr_idx) = 7 * (i ^ v0)
                                                    + ((i + 51) ^ (*(_BYTE *)(base64_encoded + curr_idx) + 69));
            ++curr_idx;
            ++*(_QWORD *)((char *)lpBuffer + 401);
          }
          else if ( error_code == (unsigned int)STATUS_ACCESS_VIOLATION )
          {
            dword_140005880[curr_idx] = STATUS_ACCESS_VIOLATION;
            for ( j = 0; j < 10; ++j )
              *(_BYTE *)(base64_encoded + curr_idx) = (*(_BYTE *)(base64_encoded + curr_idx) + j + 85) ^ 7;
            ++curr_idx;
            *(_QWORD *)((char *)lpBuffer + 401) += 7i64;
          }
          else if ( error_code == (unsigned int)STATUS_ILLEGAL_INSTRUCTION )
          {
            dword_140005880[curr_idx] = STATUS_ILLEGAL_INSTRUCTION;
            for ( k = 0; k < 10; ++k )
              *(_BYTE *)(base64_encoded + curr_idx) = (*(char *)(base64_encoded + curr_idx) << (k % 3)) & 0x4F ^ (91 * ((k + v0) ^ *(_BYTE *)(base64_encoded + curr_idx)) + k + (v0 >> (((k >> 31) ^ k & 1) - (k >> 31))));
            ++curr_idx;
            *(_QWORD *)((char *)lpBuffer + 401) += 2i64;
          }
          else if ( error_code == (unsigned int)STATUS_INTEGER_DIVIDE_BY_ZERO )
          {
            dword_140005880[curr_idx] = STATUS_INTEGER_DIVIDE_BY_ZERO;
            for ( m = 0; m < 10; ++m )
              *(_BYTE *)(base64_encoded + curr_idx) = (m ^ v0)
                                                    + 93
                                                    * ((m + v0) ^ (3 * v0
                                                                 + m
                                                                 + *(_BYTE *)(base64_encoded + curr_idx)
                                                                 + 4 * m));
            ++curr_idx;
            *(_QWORD *)((char *)lpBuffer + 401) += 3i64;
          }
          else if ( error_code == STATUS_PRIVILEGED_INSTRUCTION )
          {
            dword_140005880[curr_idx] = STATUS_PRIVILEGED_INSTRUCTION;
            for ( n = 0; n < 10; ++n )
              *(_BYTE *)(base64_encoded + curr_idx) = (77
                                                     * ((7 * n) ^ (*(char *)(base64_encoded + curr_idx)
                                                                 + (v0 << (n % 3))
                                                                 + 45))
                                                     + n
                                                     + v0)
                                                    % 255;
            ++curr_idx;
            *(_QWORD *)((char *)lpBuffer + 401) += 3i64;
          }
          WriteFile(hNamedPipe, lpBuffer, 0x600u, &NumberOfBytesWritten, 0i64);
          break;
        case 1:
          memset(data, 0, sizeof(data));
          v10 = -1i64;
          do
            ++v10;
          while ( *((_BYTE *)lpBuffer + v10 + 1) );
          qmemcpy(data, (char *)lpBuffer + 1, v10);
          memset((void *)base64_encoded, 0, 0x100ui64);
          len_data = -1i64;
          do
            ++len_data;
          while ( data[len_data] );
          base64_encoded = (__int64)base64_encode((__int64)data, len_data);
          v12 = -1i64;
          do
            ++v12;
          while ( *(_BYTE *)(base64_encoded + v12) );
          len_base64_encoded_string = v12;
          WriteFile(hNamedPipe, lpBuffer, 0x600u, &NumberOfBytesWritten, 0i64);
          break;
        case 8:
          if ( curr_idx >= len_base64_encoded_string )
          {
            v1 = 1;
            for ( ii = 0; ; ++ii )
            {
              if ( ii >= 64 )
                goto LABEL_52;
              if ( *(char *)(base64_encoded + ii) != target[ii] )
                break;
            }
            v1 = 0;
LABEL_52:
            *(_BYTE *)lpBuffer = 0xCC;
            WriteFile(hNamedPipe, lpBuffer, 1u, &NumberOfBytesWritten, 0i64);
            checking_done = 1;
            curr_idx = 0;
            if ( v1 )
            {
              MessageBoxW(0i64, L"Correct", L"Correct", 0x40000u);
            }
            else
            {
              MessageBoxW(0i64, L"Wrong", L"Wrong", 0x40000u);
              call_destroy();
            }
          }
          else
          {
            *(_BYTE *)lpBuffer = *(_BYTE *)(base64_encoded + curr_idx);
            if ( !checking_done )
            {
              *(_BYTE *)lpBuffer = 0xCC;
              WriteFile(hNamedPipe, lpBuffer, 1u, &NumberOfBytesWritten, 0i64);
              curr_idx = 0;
              checking_done = 1;
              CloseHandle(hNamedPipe);
              MessageBoxW(0i64, L"Wrong", L"Wrong", 0x40000u);
              call_destroy();
            }
            WriteFile(hNamedPipe, lpBuffer, 1u, &NumberOfBytesWritten, 0i64);
          }
          break;
        case 0x54:
          ExitProcess(0);
        case 0x55:
          call_destroy();
          ExitProcess(0);
      }
    }
    CloseHandle(hNamedPipe);
  }
}
```

`Windows Update Checker 2.exe` sẽ đọc dữ liệu từ pipe, xử lý theo command:
- `1`: Nhận chuỗi, encode chuỗi thành base64, lưu vào `base64_encoded`.
- `5`: Nhận mã lỗi exception, xử lý theo mã lỗi.
- `8`: Nếu đã xử lý hết chuỗi `base64_encoded`, so sánh với chuỗi `target`, nếu đúng thì hiện messagebox "Correct", ngược lại hiện messagebox "Wrong" và gọi hàm `call_destroy`. Nếu chưa xử lý hết chuỗi, gửi ký tự tiếp theo trong `base64_encoded` qua pipe.
- `0x54`: ExitProcess.
- `0x55`: Gọi hàm `call_destroy`, sau đó ExitProcess.

Từ đây, ta cần tìm chuỗi `data` sao cho sau khi encode thành base64 và thực hiện biến đổi, ta sẽ có chuỗi `target`.

Tóm tắt lại quá trình xử lý input:
1. `KMACTF.exe` nhận input, gửi qua pipe. (command `1`)
2. `Windows Update Checker 2.exe` nhận input, encode thành base64, gửi qua pipe.
3. `Windows Update Checker 2.exe` gửi từng ký tự của base64 qua pipe, `KMACTF.exe` nhận. (command `8`)
4. `KMACTF.exe` nhận ký tự (lúc này đang chạy hàm `communicate`), gọi một trong các hàm tạo lỗi dựa vào ký tự nhận được.
5. `KMACTF.exe` gửi mã lỗi exception qua pipe. (command `5`)
6. `Windows Update Checker 2.exe` nhận mã lỗi, so với `expected_error_code[curr_idx]`(`curr_idx` là index của ký tự base64 đang xử lý), nếu khớp thì xử lý theo mã lỗi, ngược lại trả về data `0xCC` (command `8`), kết thúc quá trình xử lý base64.
7. Lặp lại từ bước 3.
8. Khi đã xử lý hết base64, so sánh với `target`.

Do chương trình biến đổi từng ký tự của base64 nên có thể dễ dàng brute force để tìm chuỗi base64 ban đầu.

Script brute force:

```cpp

#include <iostream>
#include <Windows.h>
#include <stdint.h>

#define STATUS_BREAKPOINT 0x80000003
#define STATUS_ACCESS_VIOLATION 0xC0000005
#define STATUS_ILLEGAL_INSTRUCTION 0xC000001D
#define STATUS_INTEGER_DIVIDE_BY_ZERO 0xC0000094
#define STATUS_PRIVILEGED_INSTRUCTION 0xC0000096


int gen_error_code(uint8_t byte) {
    if (byte == 0x2B || byte == 0x32 || byte == 0x48 || byte == 0x52 || byte == 0x58 || byte == 0x5A ||
        byte == 0x61 || byte == 0x6C || byte == 0x6D || byte == 0x6F || byte == 0x73 || byte == 0x76 || byte == 0x78) {
        return STATUS_ILLEGAL_INSTRUCTION;
    }
    else if (byte == 0x2F || byte == 0x43 || byte == 0x44 || byte == 0x46 || byte == 0x4E || byte == 0x50 ||
        byte == 0x63 || byte == 0x6A || byte == 0x6B || byte == 0x70 || byte == 0x71 || byte == 0x74 || byte == 0x77) {
        return STATUS_BREAKPOINT;
    }
    else if (byte == 0x30 || byte == 0x36 || byte == 0x37 || byte == 0x41 || byte == 0x42 || byte == 0x4B ||
        byte == 0x4C || byte == 0x4F || byte == 0x54 || byte == 0x62 || byte == 0x67 || byte == 0x79 || byte == 0x7A) {
        return STATUS_ACCESS_VIOLATION;
    }
    else if (byte == 0x31 || byte == 0x34 || byte == 0x35 || byte == 0x38 || byte == 0x3D || byte == 0x49 ||
        byte == 0x4A || byte == 0x55 || byte == 0x57 || byte == 0x64 || byte == 0x66 || byte == 0x72 || byte == 0x75) {
        return STATUS_PRIVILEGED_INSTRUCTION;
    }
    else if (byte == 0x33 || byte == 0x39 || byte == 0x45 || byte == 0x47 || byte == 0x4D || byte == 0x51 ||
        byte == 0x53 || byte == 0x56 || byte == 0x59 || byte == 0x65 || byte == 0x68 || byte == 0x69 || byte == 0x6E) {
        return STATUS_INTEGER_DIVIDE_BY_ZERO;
    }
    else if (byte == 0xCC) {
        // ExitProcess(0);
        // Placeholder for exit process
    }
    return 0; // Default return value if no condition is met
}

int main() {
    int predefined_code[] = { 
        0xc0000094, 0xc0000005, 0xc0000096, 0xc0000005, 0xc0000094, 0xc0000096, 0xc000001d, 0xc0000094, 0xc0000094, 0xc000001d, 0xc0000094, 0xc000001d, 0xc0000096, 0xc0000096, 0xc0000094, 0x80000003, 0xc0000094, 0xc0000096, 0xc0000096, 0xc0000096, 0xc000001d, 0xc0000094, 0xc000001d, 0x80000003, 0xc0000005, 0xc0000096, 0xc0000094, 0xc0000005, 0xc000001d, 0xc000001d, 0x80000003, 0xc0000005, 0xc000001d, 0xc0000094, 0xc0000094, 0xc0000096, 0xc0000005, 0xc0000094, 0xc0000094, 0xc0000096, 0xc000001d, 0xc0000094, 0xc000001d, 0xc000001d, 0xc000001d, 0x80000003, 0xc0000094, 0xc0000005, 0xc0000005, 0xc000001d, 0xc000001d, 0xc0000094, 0xc0000094, 0xc0000005, 0xc0000094, 0xc000001d, 0xc0000096, 0xc0000096, 0xc0000005, 0x80000003, 0xc0000096, 0xc0000094, 0xc0000096, 0xc0000096 };

    char target[] = {
        0x72, 0xBB, 0xB2, 0xCD, 0x58, 0xB2, 0x81, 0x0E, 0xA4, 0xB1,
        0xED, 0xDB, 0x84, 0xB2, 0xC0, 0xAA, 0x60, 0xD0, 0xE8, 0xE8,
        0xB0, 0x12, 0x81, 0x1E, 0xED, 0xD0, 0xF3, 0x05, 0xB0, 0xB1,
        0x04, 0x04, 0x7D, 0xF3, 0xC0, 0xE8, 0xED, 0x12, 0xF3, 0xC2,
        0x7D, 0x0E, 0x0E, 0x0E, 0x7D, 0x04, 0xC0, 0xBB, 0xED, 0xB1,
        0x81, 0xED, 0xA4, 0xCF, 0xC0, 0x68, 0x84, 0xD0, 0xE2, 0x1B,
        0xC2, 0x58, 0x30, 0x30, 0x00
    };

    int error_code;

    char base64_encode[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    size_t length = sizeof(base64_encode) / sizeof(base64_encode[0]);
    BYTE curr_char;

    for (int curr_idx = 0; curr_idx < length; curr_idx++) {
        // Brute force the base64
        for (int i = 0; i < 256; i++) {
            base64_encode[curr_idx] = i;
            error_code = gen_error_code(base64_encode[curr_idx]);
            // std::cout << "index: " << curr_idx << " char: " << (char)(BYTE)base64_encode[curr_idx] << " error code: " << std::hex << error_code << std::endl;

            if (predefined_code[curr_idx] != error_code)
                // std::cout << "Error code mismatched!" << std::endl;
                continue;
            curr_char = base64_encode[curr_idx];

            if (error_code == (unsigned int)STATUS_BREAKPOINT)
            {
                for (int i = 0; i < 10; ++i)
                    base64_encode[curr_idx] = 7 * (i ^ curr_char) + ((i + 51) ^ (base64_encode[curr_idx] + 69));
            }
            else if (error_code == (unsigned int)STATUS_ACCESS_VIOLATION)
            {
                for (int j = 0; j < 10; ++j)
                    base64_encode[curr_idx] = (base64_encode[curr_idx] + j + 85) ^ 7;
            }
            else if (error_code == (unsigned int)STATUS_ILLEGAL_INSTRUCTION)
            {
                for (int k = 0; k < 10; ++k)
                    base64_encode[curr_idx] = (base64_encode[curr_idx] << (k % 3)) & 0x4F ^ (91 * ((k + curr_char) ^ base64_encode[curr_idx])
                        + k
                        + (curr_char >> (((k >> 31) ^ k & 1) - (k >> 31))));
            }
            else if (error_code == (unsigned int)STATUS_INTEGER_DIVIDE_BY_ZERO)
            {
                for (int m = 0; m < 10; ++m)
                    base64_encode[curr_idx] = (m ^ curr_char) + 93 * ((m + curr_char) ^ (3 * curr_char + m + base64_encode[curr_idx] + 4 * m));
            }
            else if (error_code == (unsigned int)STATUS_PRIVILEGED_INSTRUCTION)
            {
                for (int n = 0; n < 10; ++n)
                    base64_encode[curr_idx] = (77 * ((7 * n) ^ (base64_encode[curr_idx] + (curr_char << (n % 3)) + 45)) + n + curr_char) % 255;
            }

            if (base64_encode[curr_idx] == target[curr_idx]) {
                std::cout << static_cast<char>(i);
                break;
            }

        }
    }
    return 0;
}
```

Chạy script trên, ta sẽ tìm được chuỗi base64: `S01BQ1RGe2hvd19tYW55X3RpbWVzX2FyZV95b3VfZGllZF90b2RheT9odWg/fQ==`.

Decode chuỗi base64 trên, ta sẽ có flag: `KMACTF{how_many_times_are_you_died_today?huh?}`.

## Hàm `call_destroy`

Trong resource file `BIN_103` chứa một file exe khác (id 130, type "BIN"), tạm gọi là `BIN_130_2`.

Hàm `call_destroy` sẽ load file `BIN_130_2` từ resource, lưu vào `%TEMP%\Windows Update Checker.exe` và chạy.

`Windows Update Checker.exe` chịu trách nhiệm cho việc troll người chơi.

Nó load một file GIF từ resource (id 101, type "GIF"), tạo một cửa sổ, hiển thị GIF đó.

Thực hiện `EnumWindows` để duyệt cửa sổ, ngoại trừ một số cửa sổ nhất định, sử dụng `SetWindowPos` để move từng cửa sổ ra khỏi màn hình.

Để đỡ rắc rối, có thể patch nop hàm này, sau đó yên tâm debug, không phải restore lại snapshot nữa.

