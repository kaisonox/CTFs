#include <cstring>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>
#include <compressapi.h>
#pragma comment(lib, "Cabinet.lib")
#include "../../packer/packer/pe.hpp"
#include <intrin.h>
#include <tlhelp32.h>

// Error codes
#define STUB_ERROR_FILE_NOT_FOUND 1
#define STUB_ERROR_DECOMPRESS_FAILED 2
#define STUB_ERROR_ALLOC_FAILED 3
#define STUB_ERROR_LOAD_DLL_FAILED 4
#define STUB_ERROR_GET_PROC_ADDRESS_FAILED 5
#define STUB_ERROR_GET_PROC_ADDRESS_BY_NAME_FAILED 6
#define STUB_ERROR_RELOCATION_FAILED 7
#define STUB_ERROR_NO_RELOCATION_DIRECTORY 8
#define STUB_ERROR_INVALID_IMAGE 9

const IMAGE_NT_HEADERS64 *get_nt_headers(const std::uint8_t *image)
{
   auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER *>(image);
   return reinterpret_cast<const IMAGE_NT_HEADERS64 *>(image + dos_header->e_lfanew);
}

struct MinimalHeaders
{
   MINIMAL_IMAGE_DOS_HEADER dos = {};
   MINIMAL_IMAGE_NT_HEADERS64 nt = {};
   std::vector<MINIMAL_IMAGE_SECTION_HEADER> sections;
};

MinimalHeaders get_minimal_headers()
{
   // find our packed headers section
   auto base = reinterpret_cast<const std::uint8_t *>(GetModuleHandleA(NULL));
   auto nt_header = get_nt_headers(base);
   auto section_table = reinterpret_cast<const IMAGE_SECTION_HEADER *>(
       reinterpret_cast<const std::uint8_t *>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader);
   const IMAGE_SECTION_HEADER *packed_headers_section = nullptr;

   for (std::uint16_t i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
   {
      if (std::memcmp(section_table[i].Name, ".pack0", 7) == 0)
      {
         packed_headers_section = &section_table[i];
         break;
      }
   }

   if (packed_headers_section == nullptr)
   {
      std::cerr << "Error: couldn't find packed headers section in binary." << std::endl;
      ExitProcess(STUB_ERROR_FILE_NOT_FOUND);
   }

   // decompress our packed headers
   auto section_start = base + packed_headers_section->VirtualAddress;
   auto unpacked_size = *reinterpret_cast<const std::size_t *>(section_start);
   auto packed_data = section_start + sizeof(std::size_t);
   auto packed_size = packed_headers_section->Misc.VirtualSize - sizeof(std::size_t);

   auto decompressed = std::vector<std::uint8_t>(unpacked_size);
   SIZE_T decompressed_size = static_cast<SIZE_T>(unpacked_size);

   COMPRESSOR_HANDLE compressor = NULL;
   if (!CreateDecompressor(COMPRESS_ALGORITHM_MSZIP, NULL, &compressor))
   {
      std::cerr << "Error: couldn't create decompressor. Error: " << GetLastError() << std::endl;
      ExitProcess(STUB_ERROR_DECOMPRESS_FAILED);
   }

   if (!Decompress(compressor, packed_data, packed_size, decompressed.data(), decompressed_size, &decompressed_size))
   {
      std::cerr << "Error: couldn't decompress headers. Error: " << GetLastError() << std::endl;
      CloseDecompressor(compressor);
      ExitProcess(STUB_ERROR_DECOMPRESS_FAILED);
   }

   CloseDecompressor(compressor);

   // Parse minimal headers from decompressed data
   MinimalHeaders headers;
   auto data = decompressed.data();

   // Copy DOS header
   memcpy(&headers.dos, data, sizeof(MINIMAL_IMAGE_DOS_HEADER));
   data += sizeof(MINIMAL_IMAGE_DOS_HEADER);

   // Copy NT headers
   memcpy(&headers.nt, data, sizeof(MINIMAL_IMAGE_NT_HEADERS64));
   data += sizeof(MINIMAL_IMAGE_NT_HEADERS64);

   // Copy section headers
   headers.sections.resize(headers.nt.FileHeader.NumberOfSections);
   memcpy(headers.sections.data(), data,
          sizeof(MINIMAL_IMAGE_SECTION_HEADER) * headers.nt.FileHeader.NumberOfSections);

   return headers;
}

std::vector<std::uint8_t> get_image()
{
   // find our packed section
   auto base = reinterpret_cast<const std::uint8_t *>(GetModuleHandleA(NULL));
   auto nt_header = get_nt_headers(base);
   auto section_table = reinterpret_cast<const IMAGE_SECTION_HEADER *>(
       reinterpret_cast<const std::uint8_t *>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader);
   const IMAGE_SECTION_HEADER *packed_section = nullptr;

   for (std::uint16_t i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
   {
      if (std::memcmp(section_table[i].Name, ".pack1", 7) == 0)
      {
         packed_section = &section_table[i];
         break;
      }
   }

   if (packed_section == nullptr)
   {
      std::cerr << "Error: couldn't find packed section in binary." << std::endl;
      ExitProcess(STUB_ERROR_FILE_NOT_FOUND);
   }

   // decompress our packed image
   auto section_start = base + packed_section->VirtualAddress;
   auto unpacked_size = *reinterpret_cast<const std::size_t *>(section_start);
   auto packed_data = section_start + sizeof(std::size_t);
   auto packed_size = packed_section->Misc.VirtualSize - sizeof(std::size_t);

   auto decompressed = std::vector<std::uint8_t>(unpacked_size);
   SIZE_T decompressed_size = static_cast<SIZE_T>(unpacked_size);

   COMPRESSOR_HANDLE compressor = NULL;
   if (!CreateDecompressor(COMPRESS_ALGORITHM_MSZIP, NULL, &compressor))
   {
      std::cerr << "Error: couldn't create decompressor. Error: " << GetLastError() << std::endl;
      ExitProcess(STUB_ERROR_DECOMPRESS_FAILED);
   }

   if (!Decompress(compressor, packed_data, packed_size, decompressed.data(), decompressed_size, &decompressed_size))
   {
      std::cerr << "Error: couldn't decompress image data. Error: " << GetLastError() << std::endl;
      CloseDecompressor(compressor);
      ExitProcess(STUB_ERROR_DECOMPRESS_FAILED);
   }

   CloseDecompressor(compressor);
   return decompressed;
}

DWORD get_section_protection(DWORD characteristics)
{
   DWORD protection = PAGE_NOACCESS;

   if (characteristics & IMAGE_SCN_MEM_EXECUTE)
   {
      if (characteristics & IMAGE_SCN_MEM_WRITE)
      {
         protection = PAGE_EXECUTE_READWRITE;
      }
      else if (characteristics & IMAGE_SCN_MEM_READ)
      {
         protection = PAGE_EXECUTE_READ;
      }
      else
      {
         protection = PAGE_EXECUTE;
      }
   }
   else if (characteristics & IMAGE_SCN_MEM_WRITE)
   {
      protection = PAGE_READWRITE;
   }
   else if (characteristics & IMAGE_SCN_MEM_READ)
   {
      protection = PAGE_READONLY;
   }

   return protection;
}

void set_section_protections(std::uint8_t *base, const MinimalHeaders &headers)
{
   for (WORD i = 0; i < headers.nt.FileHeader.NumberOfSections; ++i)
   {
      DWORD protection = get_section_protection(headers.sections[i].Characteristics);
      DWORD old_protection;

      if (!VirtualProtect(base + headers.sections[i].VirtualAddress,
                          headers.sections[i].SizeOfRawData,
                          protection,
                          &old_protection))
      {
         std::cerr << "Error: failed to set section protection. Error: " << GetLastError() << std::endl;
         ExitProcess(STUB_ERROR_ALLOC_FAILED);
      }
   }
}

std::uint8_t *load_image(const std::vector<std::uint8_t> &image, const MinimalHeaders &headers)
{
   // create a new VirtualAlloc'd buffer with read and write privileges
   auto image_size = headers.nt.OptionalHeader.SizeOfImage;
   auto base = reinterpret_cast<std::uint8_t *>(VirtualAlloc(nullptr,
                                                             image_size,
                                                             MEM_COMMIT | MEM_RESERVE,
                                                             PAGE_READWRITE));

   if (base == nullptr)
   {
      std::cerr << "Error: VirtualAlloc failed: Windows error " << GetLastError() << std::endl;
      ExitProcess(STUB_ERROR_ALLOC_FAILED);
   }

   // Zero initialize the entire buffer
   std::memset(base, 0, image_size);

   // Copy sections to their proper locations
   size_t image_offset = 0;
   for (WORD i = 0; i < headers.nt.FileHeader.NumberOfSections; ++i)
   {
      if (headers.sections[i].SizeOfRawData > 0)
      {
         std::memcpy(base + headers.sections[i].VirtualAddress,
                     image.data() + image_offset,
                     headers.sections[i].SizeOfRawData);
         image_offset += headers.sections[i].SizeOfRawData;
      }
   }

   return base;
}

// Helper function to create an intermediate function
std::uint8_t *create_intermediate_function(std::uint8_t *base, std::uint8_t *target_function)
{
   // Allocate memory for the intermediate function
   // We need 14 bytes for the function code
   auto intermediate = reinterpret_cast<std::uint8_t *>(VirtualAlloc(nullptr,
                                                                     14,
                                                                     MEM_COMMIT | MEM_RESERVE,
                                                                     PAGE_EXECUTE_READWRITE));
   if (!intermediate)
   {
      std::cerr << "Error: failed to allocate intermediate function. Error: " << GetLastError() << std::endl;
      ExitProcess(STUB_ERROR_ALLOC_FAILED);
   }

   // Create the intermediate function code:
   // mov rax, target_function
   // jmp rax
   intermediate[0] = 0x48; // REX.W prefix
   intermediate[1] = 0xB8; // MOV RAX, imm64
   *reinterpret_cast<std::uint64_t *>(&intermediate[2]) = reinterpret_cast<std::uint64_t>(target_function);
   intermediate[10] = 0xFF; // JMP RAX
   intermediate[11] = 0xE0;

   return intermediate;
}

// List of DLLs that are safe to redirect (don't use vtables)
const char *safe_redirect_dlls[] = {
    "kernel32.dll",
    "ntdll.dll",
    "advapi32.dll",
    "user32.dll",
    "gdi32.dll",
    "comdlg32.dll",
    "shell32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "ws2_32.dll",
    "wininet.dll",
    "crypt32.dll",
    "shlwapi.dll",
    "msvcrt.dll",
    "version.dll",
    "psapi.dll",
    "iphlpapi.dll",
    "secur32.dll",
    "wtsapi32.dll",
    "netapi32.dll",
    nullptr // Sentinel
};

bool is_safe_to_redirect(const char *dll_name)
{
   // Convert to lowercase for comparison
   char lower_dll[MAX_PATH];
   strcpy_s(lower_dll, dll_name);
   _strlwr_s(lower_dll);

   // Check against our list
   for (int i = 0; safe_redirect_dlls[i] != nullptr; i++)
   {
      if (_stricmp(lower_dll, safe_redirect_dlls[i]) == 0)
      {
         return true;
      }
   }
   return false;
}

void load_imports(std::uint8_t *image, const MinimalHeaders &headers)
{
   // get the import table directory entry
   auto directory_entry = headers.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

   // if there are no imports, that's fine-- return because there's nothing to do.
   if (directory_entry.VirtualAddress == 0)
   {
      return;
   }

   // get a pointer to the import descriptor array
   auto import_table = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(image + directory_entry.VirtualAddress);

   // when we reach an OriginalFirstThunk value that is zero, that marks the end of our array.
   while (import_table->OriginalFirstThunk != 0)
   {
      // get a string pointer to the DLL to load.
      auto dll_name = reinterpret_cast<char *>(image + import_table->Name);

      // load the DLL with our import.
      auto dll_import = LoadLibraryA(dll_name);

      if (dll_import == nullptr)
      {
         std::cerr << "Error: failed to load DLL from import table: " << dll_name << std::endl;
         ExitProcess(STUB_ERROR_LOAD_DLL_FAILED);
      }

      // load the array which contains our import entries
      auto lookup_table = reinterpret_cast<IMAGE_THUNK_DATA64 *>(image + import_table->OriginalFirstThunk);

      // load the array which will contain our resolved imports
      auto address_table = reinterpret_cast<IMAGE_THUNK_DATA64 *>(image + import_table->FirstThunk);

      // Check if this DLL is safe to redirect
      bool safe_to_redirect = is_safe_to_redirect(dll_name);

      while (lookup_table->u1.AddressOfData != 0)
      {
         FARPROC function = nullptr;
         auto lookup_address = lookup_table->u1.AddressOfData;

         if ((lookup_address & IMAGE_ORDINAL_FLAG64) != 0)
         {
            function = GetProcAddress(dll_import,
                                      reinterpret_cast<LPSTR>(lookup_address & 0xFFFFFFFF));

            if (function == nullptr)
            {
               std::cerr << "Error: failed ordinal lookup for " << dll_name << ": " << (lookup_address & 0xFFFFFFFF) << std::endl;
               ExitProcess(STUB_ERROR_GET_PROC_ADDRESS_FAILED);
            }
         }
         else
         {
            auto import_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(image + lookup_address);
            function = GetProcAddress(dll_import, import_name->Name);

            if (function == nullptr)
            {
               std::cerr << "Error: failed named lookup: " << dll_name << "!" << import_name->Name << std::endl;
               ExitProcess(STUB_ERROR_GET_PROC_ADDRESS_BY_NAME_FAILED);
            }

            // Zero out the function name and hint after use
            std::memset(import_name->Name, 0, strlen(import_name->Name));
            import_name->Hint = 0;
         }

         // Only create intermediate functions for DLLs that are safe to redirect
         if (safe_to_redirect)
         {
            auto intermediate = create_intermediate_function(image, reinterpret_cast<std::uint8_t *>(function));
            address_table->u1.Function = reinterpret_cast<std::uint64_t>(intermediate);
         }
         else
         {
            // For unsafe DLLs, use the function address directly
            address_table->u1.Function = reinterpret_cast<std::uint64_t>(function);
         }

         ++lookup_table;
         ++address_table;
      }

      // Zero out the DLL name after use
      std::memset(dll_name, 0, strlen(dll_name));

      ++import_table;
   }

   // Zero out the entire import directory
   std::memset(image + directory_entry.VirtualAddress, 0, directory_entry.Size);
}

void relocate(std::uint8_t *image, const MinimalHeaders &headers)
{
   // first, check if we can even relocate the image
   if ((headers.nt.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0)
   {
      std::cerr << "Error: image cannot be relocated." << std::endl;
      ExitProcess(STUB_ERROR_RELOCATION_FAILED);
   }

   // once we know we can relocate the image, make sure a relocation directory is present
   auto directory_entry = headers.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

   if (directory_entry.VirtualAddress == 0)
   {
      std::cerr << "Error: image can be relocated, but contains no relocation directory." << std::endl;
      ExitProcess(STUB_ERROR_NO_RELOCATION_DIRECTORY);
   }

   // calculate the difference between the image base in the compiled image
   // and the current virtually allocated image
   std::uintptr_t delta = reinterpret_cast<std::uintptr_t>(image) - headers.nt.OptionalHeader.ImageBase;

   // get the relocation table
   auto relocation_table = reinterpret_cast<IMAGE_BASE_RELOCATION *>(image + directory_entry.VirtualAddress);
   auto relocation_table_end = reinterpret_cast<std::uint8_t *>(relocation_table);

   // when the virtual address for our relocation header is null,
   // we've reached the end of the relocation table
   while (relocation_table->VirtualAddress != 0)
   {
      std::size_t relocations = (relocation_table->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
      auto relocation_data = reinterpret_cast<std::uint16_t *>(&relocation_table[1]);

      for (std::size_t i = 0; i < relocations; ++i)
      {
         auto relocation = relocation_data[i];
         std::uint16_t type = relocation >> 12;
         std::uint16_t offset = relocation & 0xFFF;
         auto ptr = reinterpret_cast<std::uintptr_t *>(image + relocation_table->VirtualAddress + offset);

         if (type == IMAGE_REL_BASED_DIR64)
            *ptr += delta;
      }

      relocation_table_end = reinterpret_cast<std::uint8_t *>(relocation_table) + relocation_table->SizeOfBlock;
      relocation_table = reinterpret_cast<IMAGE_BASE_RELOCATION *>(relocation_table_end);
   }

   // Zero out the entire relocation directory
   std::memset(image + directory_entry.VirtualAddress, 0, directory_entry.Size);
}

void restore_headers(std::uint8_t *image, const MinimalHeaders &headers)
{
   // Restore DOS header
   auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(image);
   dos_header->e_magic = IMAGE_DOS_SIGNATURE;
   dos_header->e_lfanew = headers.dos.e_lfanew;

   // Restore NT headers
   auto nt_header = reinterpret_cast<IMAGE_NT_HEADERS64 *>(image + dos_header->e_lfanew);
   nt_header->Signature = IMAGE_NT_SIGNATURE;

   // Restore FileHeader
   nt_header->FileHeader.Machine = headers.nt.FileHeader.Machine;
   nt_header->FileHeader.NumberOfSections = headers.nt.FileHeader.NumberOfSections;
   nt_header->FileHeader.SizeOfOptionalHeader = headers.nt.FileHeader.SizeOfOptionalHeader;
   nt_header->FileHeader.Characteristics = headers.nt.FileHeader.Characteristics;

   // Restore OptionalHeader
   nt_header->OptionalHeader.Magic = headers.nt.OptionalHeader.Magic;
   nt_header->OptionalHeader.AddressOfEntryPoint = headers.nt.OptionalHeader.AddressOfEntryPoint;
   nt_header->OptionalHeader.ImageBase = headers.nt.OptionalHeader.ImageBase;
   nt_header->OptionalHeader.SectionAlignment = headers.nt.OptionalHeader.SectionAlignment;
   nt_header->OptionalHeader.FileAlignment = headers.nt.OptionalHeader.FileAlignment;
   nt_header->OptionalHeader.SizeOfImage = headers.nt.OptionalHeader.SizeOfImage;
   nt_header->OptionalHeader.SizeOfHeaders = headers.nt.OptionalHeader.SizeOfHeaders;
   nt_header->OptionalHeader.Subsystem = headers.nt.OptionalHeader.Subsystem;
   nt_header->OptionalHeader.DllCharacteristics = headers.nt.OptionalHeader.DllCharacteristics;

   // Restore Data Directories
   memcpy(&nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
          &headers.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
          sizeof(IMAGE_DATA_DIRECTORY));
   memcpy(&nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC],
          &headers.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC],
          sizeof(IMAGE_DATA_DIRECTORY));

   // Restore Section Headers
   auto section_table = reinterpret_cast<IMAGE_SECTION_HEADER *>(
       reinterpret_cast<std::uint8_t *>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader);

   for (WORD i = 0; i < headers.nt.FileHeader.NumberOfSections; ++i)
   {
      memcpy(section_table[i].Name, headers.sections[i].Name, IMAGE_SIZEOF_SHORT_NAME);
      section_table[i].Misc.VirtualSize = headers.sections[i].VirtualSize;
      section_table[i].VirtualAddress = headers.sections[i].VirtualAddress;
      section_table[i].SizeOfRawData = headers.sections[i].SizeOfRawData;
      section_table[i].PointerToRawData = headers.sections[i].PointerToRawData;
      section_table[i].Characteristics = headers.sections[i].Characteristics;
   }
}

// Simple XOR-based encoder/decoder
std::uint64_t encode_address(std::uint64_t address, std::uint64_t key)
{
   return address ^ key;
}

// Custom exception handler
LONG WINAPI CustomExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
   if (ExceptionInfo->ExceptionRecord->ExceptionCode == 0xDEADBEEF) // Our custom exception code
   {
      std::cerr << "Security violation detected: VM or debugger detected!" << std::endl;
      return EXCEPTION_EXECUTE_HANDLER;
   }
   return EXCEPTION_CONTINUE_SEARCH;
}

// Check if parent process is a debugger
bool is_parent_debugger()
{
   HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
   if (snapshot == INVALID_HANDLE_VALUE)
   {
      return false;
   }

   PROCESSENTRY32W pe32;
   pe32.dwSize = sizeof(PROCESSENTRY32W);

   // Get current process ID
   DWORD currentProcessId = GetCurrentProcessId();
   DWORD parentProcessId = 0;

   // Find parent process ID
   if (Process32FirstW(snapshot, &pe32))
   {
      do
      {
         if (pe32.th32ProcessID == currentProcessId)
         {
            parentProcessId = pe32.th32ParentProcessID;
            break;
         }
      } while (Process32NextW(snapshot, &pe32));
   }

   CloseHandle(snapshot);

   if (parentProcessId == 0)
   {
      return false;
   }

   // List of common debugger process names
   const wchar_t *debugger_processes[] = {
       L"windbg.exe",
       L"ollydbg.exe",
       L"x64dbg.exe",
       L"x32dbg.exe",
       L"ida.exe",
       L"ida64.exe",
       L"devenv.exe",  // Visual Studio
       L"vsdebug.exe", // Visual Studio Debugger
       nullptr};

   // Check if parent process is a debugger
   snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
   if (snapshot == INVALID_HANDLE_VALUE)
   {
      return false;
   }

   pe32.dwSize = sizeof(PROCESSENTRY32W);

   if (Process32FirstW(snapshot, &pe32))
   {
      do
      {
         if (pe32.th32ProcessID == parentProcessId)
         {
            for (int i = 0; debugger_processes[i] != nullptr; i++)
            {
               if (_wcsicmp(pe32.szExeFile, debugger_processes[i]) == 0)
               {
                  CloseHandle(snapshot);
                  return true;
               }
            }
            break;
         }
      } while (Process32NextW(snapshot, &pe32));
   }

   CloseHandle(snapshot);
   return false;
}

// Modified anti-debugging check
bool is_debugger_present()
{
   BOOL isDebuggerPresent = FALSE;
   CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
   if (isDebuggerPresent || IsDebuggerPresent() || is_parent_debugger())
   {
      RaiseException(0xDEADBEEF, 0, 0, nullptr);
      return true;
   }
   return false;
}

// Check for hardware breakpoints
bool has_hardware_breakpoints()
{
   CONTEXT ctx = {};
   ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

   if (!GetThreadContext(GetCurrentThread(), &ctx))
   {
      return false;
   }

   // Check DR0-DR3 for any non-zero values
   return (ctx.Dr0 != 0) || (ctx.Dr1 != 0) || (ctx.Dr2 != 0) || (ctx.Dr3 != 0);
}

// Check for VM processes
bool check_vm_processes()
{
   HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
   if (snapshot == INVALID_HANDLE_VALUE)
   {
      return false;
   }

   PROCESSENTRY32W pe32;
   pe32.dwSize = sizeof(PROCESSENTRY32W);

   if (!Process32FirstW(snapshot, &pe32))
   {
      CloseHandle(snapshot);
      return false;
   }

   // List of common VM-related processes
   const wchar_t *vm_processes[] = {
       L"vboxservice.exe",
       L"vboxtray.exe",
       L"vmtoolsd.exe",
       L"vmwaretray.exe",
       L"vmwareuser.exe",
       L"vmusrvc.exe",
       L"qemu-ga.exe",
       nullptr};

   do
   {
      for (int i = 0; vm_processes[i] != nullptr; i++)
      {
         if (_wcsicmp(pe32.szExeFile, vm_processes[i]) == 0)
         {
            CloseHandle(snapshot);
            return true;
         }
      }
   } while (Process32NextW(snapshot, &pe32));

   CloseHandle(snapshot);
   return false;
}

// Modified VM check to raise exception
bool is_running_in_vm()
{
   // Check for VM processes
   if (check_vm_processes())
   {
      RaiseException(0xDEADBEEF, 0, 0, nullptr);
      return true;
   }

   return false;
}

// Entry point decoder with anti-debugging
std::uint64_t decode_entry_point(std::uint64_t encoded_address, std::uint64_t key)
{
   // Anti-debugging checks
   if (is_debugger_present() || has_hardware_breakpoints())
   {
      // If debugger is present or hardware breakpoints are set, return a bogus address
      return 0;
   }

   // Decode the address
   return encoded_address ^ key;
}

// Function pointer type for the entry point
typedef void (*EntryPointFunc)();

// Indirect jump to entry point with anti-debugging
void jump_to_entry_point(std::uint64_t address)
{
   // Additional anti-debugging check
   if (is_debugger_present() || has_hardware_breakpoints())
   {
      // If debugger is detected, jump to invalid address
      reinterpret_cast<EntryPointFunc>(0)();
      return;
   }

   // Use interlocked operations consistently
   void *volatile *pAddress = reinterpret_cast<void *volatile *>(&address);
   void *target = reinterpret_cast<void *>(address);
   void *result = _InterlockedExchangePointer(pAddress, target);

   // Call the entry point using the result of the interlocked operation
   reinterpret_cast<EntryPointFunc>(result)();
}

// Stage identifiers
enum class Stage
{
   INIT,
   LOAD,
   FIXUP,
   PROTECT,
   EXECUTE
};

// Obfuscated stage transition function
Stage next_stage(Stage current)
{
   // Use a simple but obfuscated transition
   return static_cast<Stage>((static_cast<int>(current) + 1) % 5);
}

// Obfuscated data structure for storing state
struct ObfuscatedState
{
   std::uint8_t *image;
   MinimalHeaders headers;
   std::vector<std::uint8_t> raw_image;
   Stage current_stage;

   // Obfuscated constructor
   ObfuscatedState() : image(nullptr), current_stage(Stage::INIT) {}
};

// Obfuscated initialization function
bool initialize_stage(ObfuscatedState &state)
{
   if (state.current_stage != Stage::INIT)
      return false;

   // Get minimal headers from .pack0
   state.headers = get_minimal_headers();
   state.current_stage = next_stage(state.current_stage);
   return true;
}

// Obfuscated loading function
bool load_stage(ObfuscatedState &state)
{
   if (state.current_stage != Stage::LOAD)
      return false;

   // Get and load the PE image
   state.raw_image = get_image();
   state.image = load_image(state.raw_image, state.headers);
   state.current_stage = next_stage(state.current_stage);
   return true;
}

// Obfuscated fixup function
bool fixup_stage(ObfuscatedState &state)
{
   if (state.current_stage != Stage::FIXUP)
      return false;

   // Fix up the image
   load_imports(state.image, state.headers);
   relocate(state.image, state.headers);
   restore_headers(state.image, state.headers);
   state.current_stage = next_stage(state.current_stage);
   return true;
}

// Obfuscated protection function
bool protect_stage(ObfuscatedState &state)
{
   if (state.current_stage != Stage::PROTECT)
      return false;

   // Set proper memory protections
   set_section_protections(state.image, state.headers);
   state.current_stage = next_stage(state.current_stage);
   return true;
}

// Obfuscated execution function
bool execute_stage(ObfuscatedState &state)
{
   if (state.current_stage != Stage::EXECUTE)
      return false;

   // Get and encode the entry point
   auto entrypoint = state.image + state.headers.nt.OptionalHeader.AddressOfEntryPoint;

   // Generate a random key for encoding
   std::uint64_t key = 0;
   for (int i = 0; i < 8; i++)
   {
      key = (key << 8) | (GetTickCount64() & 0xFF);
   }

   // Encode the entry point address
   std::uint64_t encoded_entrypoint = encode_address(reinterpret_cast<std::uint64_t>(entrypoint), key);

   // Decode and jump to the entry point
   std::uint64_t decoded_entrypoint = decode_entry_point(encoded_entrypoint, key);
   if (decoded_entrypoint != 0)
   {
      jump_to_entry_point(decoded_entrypoint);
   }

   return true;
}

// Modified execute_workflow to use exception handling
void execute_workflow()
{
   // Register our custom exception handler
   SetUnhandledExceptionFilter(CustomExceptionHandler);

   // Check for VM before proceeding
   if (is_running_in_vm())
   {
      // This will raise an exception that our handler will catch
      return;
   }

   ObfuscatedState state;

   // Execute stages in sequence with obfuscated transitions
   while (true)
   {
      // Additional VM check at each stage
      if (is_running_in_vm())
      {
         return;
      }

      switch (state.current_stage)
      {
      case Stage::INIT:
         if (!initialize_stage(state))
            return;
         break;
      case Stage::LOAD:
         if (!load_stage(state))
            return;
         break;
      case Stage::FIXUP:
         if (!fixup_stage(state))
            return;
         break;
      case Stage::PROTECT:
         if (!protect_stage(state))
            return;
         break;
      case Stage::EXECUTE:
         // Final execution stage
         execute_stage(state);
         return;
      default:
         return;
      }
   }
}

int main()
{
   __try
   {
      // Start the obfuscated workflow
      execute_workflow();
   }
   __except (CustomExceptionHandler(GetExceptionInformation()))
   {
      // Exception was handled by our handler
      return 1;
   }
   return 0;
}