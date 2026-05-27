/*
 * payload.c -- Nono CTF native JIT patch payload
 *
 * Build (VS x64 Native Tools Command Prompt):
 *   build.bat release
 *   build.bat debug
 */
#define WIN32_LEAN_AND_MEAN
#include <intrin.h>
#include <windows.h>

#include "correct_data.h"

/* Define DEBUG or build with /DDEBUG to enable file/OutputDebugString logging. */
/* #define DEBUG */

typedef unsigned char u8;
typedef signed int    s32;

void WINAPI ShellMain(void);

#pragma function(memset)
void* __cdecl memset(void* dst, int value, size_t count) {
    volatile u8* p;
    size_t i;

    p = (volatile u8*)dst;
    for (i = 0; i < count; i++) {
        p[i] = (u8)value;
    }
    return dst;
}

#define TRAMP_SLOT_SIZE 80
#define TRAMP_GROUP_SIZE (CLUE_GROUP_ITEMS * TRAMP_SLOT_SIZE)
#define ABS_JMP_SIZE 13
#define ADD_EDX_1_SIZE 3
#define OP_KEY 0xA7

typedef struct {
    BOOL    (WINAPI *VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    LPVOID  (WINAPI *VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    BOOL    (WINAPI *FlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
    HANDLE  (WINAPI *CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    BOOL    (WINAPI *CloseHandle)(HANDLE);
    VOID    (WINAPI *Sleep)(DWORD);
    BOOL    (WINAPI *IsDebuggerPresent)(void);
#ifdef DEBUG
    HANDLE  (WINAPI *CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    BOOL    (WINAPI *WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    VOID    (WINAPI *OutputDebugStringA)(LPCSTR);
#endif
} Api;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_X;

typedef struct {
    ULONG      Length;
    BOOLEAN    Initialized;
    void*      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_X;

typedef struct {
    LIST_ENTRY       InLoadOrderLinks;
    LIST_ENTRY       InMemoryOrderLinks;
    LIST_ENTRY       InInitializationOrderLinks;
    void*            DllBase;
    void*            EntryPoint;
    ULONG            SizeOfImage;
    UNICODE_STRING_X FullDllName;
    UNICODE_STRING_X BaseDllName;
} LDR_DATA_TABLE_ENTRY_X;

typedef struct {
    u8              Reserved0[0x18];
    PEB_LDR_DATA_X* Ldr;
} PEB_X;

static Api g_api;
static int g_api_ready;

#define H_KERNEL32_DLL            0x12CAD9BDu
#define H_KERNELBASE_DLL          0x869EC7F7u
#define H_VIRTUALPROTECT          0x88FBAF78u
#define H_VIRTUALALLOC            0xB709F45Eu
#define H_FLUSHINSTRUCTIONCACHE   0x3C421D43u
#define H_CREATETHREAD            0x90A40A73u
#define H_CLOSEHANDLE             0x3EC059B4u
#define H_SLEEP                   0x892CBD5Cu
#define H_ISDEBUGGERPRESENT       0x7FF15F05u
#define H_CLRJIT_DLL              0x3BE5BFF8u
#define H_GETJIT                  0x9C43B3BDu
#ifdef DEBUG
#define H_CREATEFILEA             0xF86FBC86u
#define H_WRITEFILE               0xF8B78299u
#define H_OUTPUTDEBUGSTRINGA      0x8D2CFAE5u
#endif

static char lower_a(char c) {
    if (c >= 'A' && c <= 'Z') return (char)(c + 32);
    return c;
}

static WCHAR lower_w(WCHAR c) {
    if (c >= L'A' && c <= L'Z') return (WCHAR)(c + 32);
    return c;
}

static u32 hash_step(u32 h, unsigned int c) {
    h = (h << 5) | (h >> 27);
    h ^= (u32)c;
    return h + 0x9E3779B9u;
}

static u32 hash_ascii_name(const char* s) {
    u32 h;

    h = 0x6D2B79F5u;
    while (*s) {
        h = hash_step(h, (unsigned int)(unsigned char)lower_a(*s));
        s++;
    }
    return h;
}

static u32 hash_unicode_name(UNICODE_STRING_X* name) {
    USHORT i;
    USHORT n;
    u32 h;

    if (!name || !name->Buffer) return 0;
    h = 0x6D2B79F5u;
    n = (USHORT)(name->Length / sizeof(WCHAR));
    for (i = 0; i < n; i++) {
        h = hash_step(h, (unsigned int)lower_w(name->Buffer[i]));
    }
    return h;
}

static HMODULE peb_find_module(u32 module_hash) {
    PEB_X* peb;
    LIST_ENTRY* head;
    LIST_ENTRY* cur;
    LDR_DATA_TABLE_ENTRY_X* entry;

    peb = (PEB_X*)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return NULL;
    head = &peb->Ldr->InMemoryOrderModuleList;
    cur = head->Flink;
    while (cur && cur != head) {
        entry = (LDR_DATA_TABLE_ENTRY_X*)((u8*)cur - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_X, InMemoryOrderLinks));
        if (hash_unicode_name(&entry->BaseDllName) == module_hash) return (HMODULE)entry->DllBase;
        cur = cur->Flink;
    }
    return NULL;
}

static FARPROC resolve_export(HMODULE module, u32 name_hash);

static FARPROC resolve_forwarder(const char* fwd) {
    char module_name[64];
    char func_name[96];
    int i;
    int j;
    HMODULE module;

    i = 0;
    while (fwd[i] && fwd[i] != '.' && i < 55) {
        module_name[i] = lower_a(fwd[i]);
        i++;
    }
    if (fwd[i] != '.') return NULL;
    module_name[i++] = '.';
    module_name[i++] = 'd';
    module_name[i++] = 'l';
    module_name[i++] = 'l';
    module_name[i] = 0;

    while (*fwd && *fwd != '.') fwd++;
    if (*fwd == '.') fwd++;

    j = 0;
    while (fwd[j] && j < 95) {
        func_name[j] = fwd[j];
        j++;
    }
    func_name[j] = 0;

    module = peb_find_module(hash_ascii_name(module_name));
    if (!module) module = peb_find_module(H_KERNELBASE_DLL);
    if (!module) return NULL;
    return resolve_export(module, hash_ascii_name(func_name));
}

static FARPROC resolve_export(HMODULE module, u32 name_hash) {
    u8* base;
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nt;
    IMAGE_DATA_DIRECTORY* dir;
    IMAGE_EXPORT_DIRECTORY* exp;
    DWORD* names;
    WORD* ords;
    DWORD* funcs;
    DWORD i;
    DWORD rva;
    char* export_name;

    if (!module) return NULL;
    base = (u8*)module;
    dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress || !dir->Size) return NULL;

    exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir->VirtualAddress);
    names = (DWORD*)(base + exp->AddressOfNames);
    ords = (WORD*)(base + exp->AddressOfNameOrdinals);
    funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (i = 0; i < exp->NumberOfNames; i++) {
        export_name = (char*)(base + names[i]);
        if (hash_ascii_name(export_name) != name_hash) continue;
        rva = funcs[ords[i]];
        if (rva >= dir->VirtualAddress && rva < dir->VirtualAddress + dir->Size) {
            return resolve_forwarder((const char*)(base + rva));
        }
        return (FARPROC)(base + rva);
    }
    return NULL;
}

static int resolve_api(void) {
    HMODULE kernel32;

    if (g_api_ready) return 1;

    kernel32 = peb_find_module(H_KERNEL32_DLL);
    if (!kernel32) return 0;

    g_api.VirtualProtect = (BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))resolve_export(kernel32, H_VIRTUALPROTECT);
    g_api.VirtualAlloc = (LPVOID (WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))resolve_export(kernel32, H_VIRTUALALLOC);
    g_api.FlushInstructionCache = (BOOL (WINAPI*)(HANDLE, LPCVOID, SIZE_T))resolve_export(kernel32, H_FLUSHINSTRUCTIONCACHE);
    g_api.CreateThread = (HANDLE (WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))resolve_export(kernel32, H_CREATETHREAD);
    g_api.CloseHandle = (BOOL (WINAPI*)(HANDLE))resolve_export(kernel32, H_CLOSEHANDLE);
    g_api.Sleep = (VOID (WINAPI*)(DWORD))resolve_export(kernel32, H_SLEEP);
    g_api.IsDebuggerPresent = (BOOL (WINAPI*)(void))resolve_export(kernel32, H_ISDEBUGGERPRESENT);
#ifdef DEBUG
    g_api.CreateFileA = (HANDLE (WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))resolve_export(kernel32, H_CREATEFILEA);
    g_api.WriteFile = (BOOL (WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))resolve_export(kernel32, H_WRITEFILE);
    g_api.OutputDebugStringA = (VOID (WINAPI*)(LPCSTR))resolve_export(kernel32, H_OUTPUTDEBUGSTRINGA);
#endif

    if (!g_api.VirtualProtect) return 0;
    if (!g_api.VirtualAlloc) return 0;
    if (!g_api.FlushInstructionCache) return 0;
    if (!g_api.CreateThread) return 0;
    if (!g_api.CloseHandle) return 0;
    if (!g_api.Sleep) return 0;
    if (!g_api.IsDebuggerPresent) return 0;
#ifdef DEBUG
    if (!g_api.CreateFileA) return 0;
    if (!g_api.WriteFile) return 0;
    if (!g_api.OutputDebugStringA) return 0;
#endif
    g_api_ready = 1;
    return 1;
}

#include "log.h"

typedef s32 (__stdcall *compileMethod_t)(
    void* thisptr, void* comp, void* info,
    u32 flags, u8** native_entry, u32* native_size);

typedef void** (*getJit_t)(void);

typedef struct {
    compileMethod_t  orig;
    void**           vtable_slot;
    int              done;
    int              skip;
} HookCtx;

static HookCtx g_ctx;
static u8*     g_deferred_entry;
static u32     g_deferred_size;

/* ---- hook logic ---- */

static u8 code_token(int id) {
    static const u8 packed[] = { 0x1D, 0x9E, 0xAE, 0x58, 0xB2 };
    return (u8)(packed[id] ^ OP_KEY);
}

static int candidate_tail(u8* p, u8* end) {
    if (p + ABS_JMP_SIZE > end) return 0;
    if (p[0] != code_token(0)) return 0;
    if (p[5] != code_token(1)) return 0;
    if (p[6] != code_token(2)) return 0;
    if (p[7] != code_token(3)) return 0;
    if (p[8] != code_token(4)) return 0;
    return 1;
}

static int locate_replay_start(u8* addr, u8* end, u8* ba, u8** out_start, int* out_mov_len) {
    if (!candidate_tail(ba, end)) return 0;

    /* mov rcx, qword ptr [rbp+disp8] */
    if (ba >= addr + 4 && ba[-4] == 0x48 && ba[-3] == 0x8B && ba[-2] == 0x4D) {
        *out_start = ba - 4;
        *out_mov_len = 4;
        return 1;
    }

    /* mov rcx, qword ptr [rsp+disp8] */
    if (ba >= addr + 5 && ba[-5] == 0x48 && ba[-4] == 0x8B && ba[-3] == 0x4C && ba[-2] == 0x24) {
        *out_start = ba - 5;
        *out_mov_len = 5;
        return 1;
    }

    /* mov rcx, qword ptr [rbp+disp32] */
    if (ba >= addr + 7 && ba[-7] == 0x48 && ba[-6] == 0x8B && ba[-5] == 0x8D) {
        *out_start = ba - 7;
        *out_mov_len = 7;
        return 1;
    }

    /* mov rcx, qword ptr [rsp+disp32] */
    if (ba >= addr + 8 && ba[-8] == 0x48 && ba[-7] == 0x8B && ba[-6] == 0x8C && ba[-5] == 0x24) {
        *out_start = ba - 8;
        *out_mov_len = 8;
        return 1;
    }

    return 0;
}

static int fits_s32(signed __int64 v) {
    if (v < -2147483647i64 - 1i64) return 0;
    if (v >  2147483647i64) return 0;
    return 1;
}

static void write_abs_jmp(u8* dst, u8* target) {
    dst[0] = 0x49;
    dst[1] = 0xBB;
    *(unsigned __int64*)(dst + 2) = (unsigned __int64)target;
    dst[10] = 0x41;
    dst[11] = 0xFF;
    dst[12] = 0xE3;
}

static void byte_fill(u8* dst, int n, u8 value) {
    volatile u8* p;
    int i;

    p = (volatile u8*)dst;
    for (i = 0; i < n; i++) {
        p[i] = value;
    }
}

static u8* alloc_near(u8* addr, u32 size) {
    u8* hint;
    u8* mem;

    hint = (addr > (u8*)0x60000000) ? addr - 0x60000000 : (u8*)0x10000;
    mem = NULL;
    while (hint < addr + 0x60000000) {
        mem = (u8*)g_api.VirtualAlloc(hint, size,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
        if (mem) return mem;
        hint += 0x10000;
    }
    return NULL;
}

static int emit_replay_chain(u8* addr, u8* end, u8** pos) {
    static u8* starts[CLUE_BLOCK_COUNT];
    static int mov_lens[CLUE_BLOCK_COUNT];
    static int block_lens[CLUE_BLOCK_COUNT];
    u8* chain_buf;
    u8* group_buf;
    u8* slot_buf;
    u8* start;
    u8* target;
    u8* thunk;
    u8* cursor;
    signed __int64 delta;
    u32 alloc_size;
    u32 value;
    s32 disp;
    int mov_len;
    int block_len;
    int emitted_len;
    int g;
    int i;
    int j;
    int idx;

    for (i = 0; i < CLUE_BLOCK_COUNT; i++) {
        if (!locate_replay_start(addr, end, pos[i], &start, &mov_len)) {
            log_d("tramp_validate_fail", i);
            return 0;
        }
        block_len = mov_len + 13;
        starts[i] = start;
        mov_lens[i] = mov_len;
        block_lens[i] = block_len;
    }

    alloc_size = CLUE_GROUP_COUNT * TRAMP_GROUP_SIZE;
    chain_buf = alloc_near(addr, alloc_size);
    log_x64("tramp_chain_buf", (unsigned __int64)chain_buf);
    if (!chain_buf) return 0;

    for (g = 0; g < CLUE_GROUP_COUNT; g++) {
        group_buf = chain_buf + g * TRAMP_GROUP_SIZE;

        for (i = 0; i < CLUE_GROUP_ITEMS; i++) {
            slot_buf  = group_buf + i * TRAMP_SLOT_SIZE;
            idx       = g * CLUE_GROUP_ITEMS + i;
            start     = starts[idx];
            block_len = block_lens[idx];
            mov_len   = mov_lens[idx];
            value     = clue_value(idx);

            byte_fill(slot_buf, TRAMP_SLOT_SIZE, 0x90);

            for (j = 0; j < mov_len; j++) slot_buf[j] = start[j];

            cursor = slot_buf + mov_len;
            cursor[0] = 0xBA;
            *(u32*)(cursor + 1) = 0;
            cursor += 5;

            if (value == 0xFFFFFFFF) {
                cursor[0] = 0x83;
                cursor[1] = 0xEA;
                cursor[2] = 0x01;
                cursor += ADD_EDX_1_SIZE;
            } else {
                if (value > 15) {
                    log_d("tramp_value_too_large", idx);
                    return 0;
                }
                for (j = 0; j < (int)value; j++) {
                    cursor[0] = 0x83;
                    cursor[1] = 0xC2;
                    cursor[2] = 0x01;
                    cursor += ADD_EDX_1_SIZE;
                }
            }

            cursor[0] = pos[idx][5];
            cursor[1] = pos[idx][6];
            cursor[2] = pos[idx][7];
            cursor[3] = pos[idx][8];
            cursor += 4;

            disp = *(s32*)(pos[idx] + 9);
            thunk = pos[idx] + 13 + disp;
            if ((cursor + 4 + ABS_JMP_SIZE) > (slot_buf + TRAMP_SLOT_SIZE)) {
                log_d("tramp_slot_too_small", idx);
                return 0;
            }
            delta = (signed __int64)(unsigned __int64)thunk -
                    (signed __int64)(unsigned __int64)(cursor + 4);
            if (!fits_s32(delta)) {
                log_d("tramp_disp_fail", idx);
                return 0;
            }
            *(s32*)cursor = (s32)delta;
            cursor += 4;
            emitted_len = (int)(cursor - slot_buf);

            if (i < CLUE_GROUP_ITEMS - 1) {
                target = group_buf + (i + 1) * TRAMP_SLOT_SIZE;
            } else {
                target = pos[g * CLUE_GROUP_ITEMS + CLUE_GROUP_ITEMS - 1] + 13;
            }
            write_abs_jmp(slot_buf + emitted_len, target);
        }
    }

    for (g = 0; g < CLUE_GROUP_COUNT; g++) {
        group_buf = chain_buf + g * TRAMP_GROUP_SIZE;
        target = group_buf;
        start = starts[g * CLUE_GROUP_ITEMS];
        block_len = block_lens[g * CLUE_GROUP_ITEMS];
        write_abs_jmp(start, target);
        for (i = ABS_JMP_SIZE; i < block_len; i++) start[i] = 0x90;
    }

    log_bytes("tramp_BA3+12", chain_buf + 3 * TRAMP_SLOT_SIZE + mov_lens[3], 12);
    g_api.FlushInstructionCache((HANDLE)(LONG_PTR)-1, chain_buf, alloc_size);
    return 1;
}


/*
 * Collect the expected add-block candidates and route execution through
 * trampolines. If validation/allocation fails, leave the method untouched.
 */
static int apply_replay_plan(u8* addr, u32 size) {
    static u8*  pos[CLUE_BLOCK_COUNT];
    u8*  end = addr + size;
    u8*  p;
    int  n;

    p = addr; n = 0;
    while (n < CLUE_BLOCK_COUNT && p + 9 <= end) {
        if (candidate_tail(p, end)) {
            pos[n++] = p;
            p += ABS_JMP_SIZE;
        } else {
            p++;
        }
    }
    if (n < CLUE_BLOCK_COUNT) return n;

    if (emit_replay_chain(addr, end, pos)) {
        log_s("tramp_patched\n");
        g_api.FlushInstructionCache((HANDLE)(LONG_PTR)-1, addr, size);
        return CLUE_BLOCK_COUNT;
    }

    log_s("tramp_failed\n");
    return 0;
}


static s32 __stdcall hook_compile_method(
    void* thisptr, void* comp, void* info,
    u32 flags, u8** native_entry, u32* native_size)
{
    HookCtx* ctx = &g_ctx;
    s32      result;
    DWORD    old;
    int      patched;
    u8*      d_entry;
    u32      d_size;

    /* --- deferred scan from previous large-method compile --- */
    if (g_deferred_entry && !ctx->done) {
        d_entry          = g_deferred_entry;
        d_size           = g_deferred_size;
        g_deferred_entry = 0;

        if (ctx->skip) {
            ctx->done = 1;           /* debugger: unhook silently, leave decoy */
        } else {
            g_api.VirtualProtect(d_entry, d_size, PAGE_EXECUTE_READWRITE, &old);
            patched = apply_replay_plan(d_entry, d_size);
            g_api.VirtualProtect(d_entry, d_size, old, &old);
            log_d("defer_patched", patched);
            if (patched == CLUE_BLOCK_COUNT) ctx->done = 1;
        }

        if (ctx->done) {
            log_s("unhook\n");
            g_api.VirtualProtect(ctx->vtable_slot, 8, PAGE_READWRITE, &old);
            *(compileMethod_t*)ctx->vtable_slot = ctx->orig;
            g_api.VirtualProtect(ctx->vtable_slot, 8, old, &old);
        }
    }

    result = ctx->orig(thisptr, comp, info, flags, native_entry, native_size);
    if (ctx->done) return result;

    /* save large methods for deferred scan */
    if (*native_size >= 0x800) {
        log_d("cm size", (int)*native_size);
        log_x64("ne_val", (unsigned __int64)*native_entry);
        g_deferred_entry = *native_entry;
        g_deferred_size  = *native_size;
    }

    return result;
}

static int anti_debug(void) {
    unsigned __int64 t0;
    unsigned __int64 t1;
    volatile int     i;
    unsigned char*   peb;
    void*            hp;

    if (g_api.IsDebuggerPresent()) return 1;
    peb = (unsigned char*)__readgsqword(0x60);
    if ((*(u32*)(peb + 0xBC)) & 0x70u) return 1;
    hp = *(void**)(peb + 0x30);
    if (*(u32*)((unsigned char*)hp + 0x74)) return 1;
    t0 = __rdtsc();
    for (i = 0; i < 1500; i++) { (void)i; }
    t1 = __rdtsc();
    if (t1 - t0 > 3000000ULL) return 1;
    return 0;
}

static int hook_install(void) {
    HMODULE  clrjit;
    getJit_t getjit;
    void**   jit_obj;
    void**   vtable;
    DWORD    old;

    log_s("hook_install\n");
    log_x64("our_hook_fn", (unsigned __int64)hook_compile_method);

    clrjit = peb_find_module(H_CLRJIT_DLL);
    log_x64("clrjit", (unsigned __int64)clrjit);
    if (!clrjit) { log_s("clrjit not found\n"); return 0; }

    getjit = (getJit_t)resolve_export(clrjit, H_GETJIT);
    log_x64("getjit", (unsigned __int64)getjit);
    if (!getjit) { log_s("getJit not found\n"); return 0; }

    jit_obj = getjit();
    log_x64("jit_obj", (unsigned __int64)jit_obj);
    if (!jit_obj) { log_s("getJit() returned NULL\n"); return 0; }

    vtable = *(void***)jit_obj;
    log_x64("vtable[0]_before", (unsigned __int64)vtable[0]);

    g_ctx.orig        = (compileMethod_t)vtable[0];
    g_ctx.vtable_slot = &vtable[0];
    g_ctx.skip        = anti_debug();
    log_d("anti_debug", g_ctx.skip);

    g_api.VirtualProtect(&vtable[0], 8, PAGE_READWRITE, &old);
    vtable[0] = (void*)hook_compile_method;
    g_api.VirtualProtect(&vtable[0], 8, old, &old);

    log_x64("vtable[0]_after", (unsigned __int64)vtable[0]);
    log_s("hook_install done\n");
    return 1;
}

static DWORD WINAPI hook_worker(LPVOID r) {
    (void)r;
    log_open();
    log_s("hook_worker\n");
    while (!peb_find_module(H_CLRJIT_DLL)) {
        g_api.Sleep(10);
    }
    while (!hook_install()) {
        g_api.Sleep(10);
    }
    return 0;
}

static void payload_start(void) {
    HANDLE th;

    if (!resolve_api()) return;
    th = g_api.CreateThread(NULL, 0, hook_worker, NULL, 0, NULL);
    if (th) g_api.CloseHandle(th);
}

void WINAPI ShellMain(void) {
    payload_start();
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH) payload_start();
    return TRUE;
}
