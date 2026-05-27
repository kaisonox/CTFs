// dump_rcdata.cpp
// Build (MSVC x64): cl /O2 /MT dump_rcdata.cpp /Fe:dump_rcdata.exe
// Usage: dump_rcdata.exe [path\to\10000.exe]

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <string>

static void pad4(int n, char out[5]) {
    out[0] = char('0' + ((n / 1000) % 10));
    out[1] = char('0' + ((n / 100) % 10));
    out[2] = char('0' + ((n / 10) % 10));
    out[3] = char('0' + (n % 10));
    out[4] = '\0';
}

int main(int argc, char** argv) {
    const char* exePath = (argc >= 2) ? argv[1] : "10000.exe";

    // 1) Load 10000.exe as data to query resources
    HMODULE hResMod = LoadLibraryExA(exePath, nullptr, LOAD_LIBRARY_AS_DATAFILE);
    if (!hResMod) {
        std::fprintf(stderr, "LoadLibraryExA(LOAD_LIBRARY_AS_DATAFILE) failed: %lu\n", GetLastError());
        return 1;
    }

    // 2) Load 10000.exe as an image without side effects to call internal functions
    HMODULE hImg = LoadLibraryExA(exePath, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!hImg) {
        std::fprintf(stderr, "LoadLibraryExA(DONT_RESOLVE_DLL_REFERENCES) failed: %lu\n", GetLastError());
        FreeLibrary(hResMod);
        return 1;
    }

    // Function pointer types (MS x64: calling conv is uniform)
    using get_decoded_size_t = long long(*)(const uint8_t* src, long long src_len, int flags);
    using decode_to_buffer_t = long long(*)(const uint8_t* src,
                                            unsigned long long dst_base,
                                            long long src_len,
                                            long long dst_len,
                                            long long dst_offset);

    // RVAs from the target binary
    const size_t RVA_GET_SIZE = 0x2690;
    const size_t RVA_DECODE   = 0x35E8;

    auto base = reinterpret_cast<uint8_t*>(hImg);
    auto get_decoded_size = reinterpret_cast<get_decoded_size_t>(base + RVA_GET_SIZE);
    auto decode_to_buffer = reinterpret_cast<decode_to_buffer_t>(base + RVA_DECODE);

    // Create output directory
    CreateDirectoryA("dlls", nullptr); // ignore error if already exists

    int found = 0, dumped = 0, errors = 0;

    for (int id = 0; id <= 9999; ++id) {
        // 3) Find RT_RCDATA (#10) with numeric ID
        HRSRC hRes = FindResourceA(hResMod, MAKEINTRESOURCEA(id), MAKEINTRESOURCEA(RT_RCDATA));
        if (!hRes) continue; // not present

        ++found;

        DWORD compSize = SizeofResource(hResMod, hRes);
        if (compSize == 0) {
            std::fprintf(stderr, "[%04d] SizeofResource returned 0, skipping\n", id);
            ++errors;
            continue;
        }

        HGLOBAL hData = LoadResource(hResMod, hRes);
        if (!hData) {
            std::fprintf(stderr, "[%04d] LoadResource failed: %lu\n", id, GetLastError());
            ++errors;
            continue;
        }
        void* pComp = LockResource(hData);
        if (!pComp) {
            std::fprintf(stderr, "[%04d] LockResource failed\n", id);
            ++errors;
            continue;
        }

        // 4) First pass: compute decompressed size
        long long outSize = get_decoded_size(reinterpret_cast<const uint8_t*>(pComp),
                                             static_cast<long long>(compSize),
                                             0);
        if (outSize <= 0) {
            std::fprintf(stderr, "[%04d] get_decoded_size returned %lld, skipping\n", id, outSize);
            ++errors;
            continue;
        }

        // 5) Allocate destination buffer
        void* dst = VirtualAlloc(nullptr, static_cast<SIZE_T>(outSize),
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!dst) {
            std::fprintf(stderr, "[%04d] VirtualAlloc(%lld) failed: %lu\n", id, outSize, GetLastError());
            ++errors;
            continue;
        }

        // 6) Decode into the buffer
        long long written = decode_to_buffer(reinterpret_cast<const uint8_t*>(pComp),
                                             reinterpret_cast<unsigned long long>(dst),
                                             static_cast<long long>(compSize),
                                             outSize,
                                             0);
        if (written < 0) {
            std::fprintf(stderr, "[%04d] decode_to_buffer failed (%lld)\n", id, written);
            VirtualFree(dst, 0, MEM_RELEASE);
            ++errors;
            continue;
        }

        // 7) Write to dlls\NNNN.dll
        char digits[5];
        pad4(id, digits);
        char outPath[MAX_PATH];
        std::snprintf(outPath, sizeof(outPath), "dlls\\%s.dll", digits);

        HANDLE hFile = CreateFileA(outPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            std::fprintf(stderr, "[%04d] CreateFile('%s') failed: %lu\n", id, outPath, GetLastError());
            VirtualFree(dst, 0, MEM_RELEASE);
            ++errors;
            continue;
        }

        DWORD toWrite = static_cast<DWORD>(written);
        DWORD writtenBytes = 0;
        BOOL ok = WriteFile(hFile, dst, toWrite, &writtenBytes, nullptr);
        CloseHandle(hFile);
        VirtualFree(dst, 0, MEM_RELEASE);

        if (!ok || writtenBytes != toWrite) {
            std::fprintf(stderr, "[%04d] WriteFile failed: ok=%d written=%lu expected=%lu\n",
                         id, (int)ok, writtenBytes, toWrite);
            ++errors;
            continue;
        }

        ++dumped;
        std::printf("[%04d] size: comp=%lu -> dec=%lld -> wrote=%lu  -> %s\n",
                    id, compSize, outSize, writtenBytes, outPath);
    }

    std::printf("Done. resources found=%d, dumped=%d, errors=%d\n", found, dumped, errors);

    FreeLibrary(hImg);
    FreeLibrary(hResMod);
    return 0;
}