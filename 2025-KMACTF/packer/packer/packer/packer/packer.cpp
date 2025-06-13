#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <windows.h>
#include <compressapi.h>
#pragma comment(lib, "Cabinet.lib")
#include "pe.hpp"

// Error codes
#define PACKER_ERROR_FILE_NOT_FOUND 1
#define PACKER_ERROR_INVALID_DOS_HEADER 2
#define PACKER_ERROR_INVALID_NT_HEADER 3
#define PACKER_ERROR_NOT_64BIT 4
#define PACKER_ERROR_RESOURCE_NOT_FOUND 5
#define PACKER_ERROR_LOAD_RESOURCE_FAILED 6
#define PACKER_ERROR_COMPRESS_FAILED 7
#define PACKER_ERROR_WRITE_FAILED 8

std::vector<std::uint8_t> read_file(const std::string &filename)
{
   std::ifstream fp(filename, std::ios::binary);

   if (!fp.is_open())
   {
      std::cerr << "Error: couldn't open file: " << filename << std::endl;
      ExitProcess(PACKER_ERROR_FILE_NOT_FOUND);
   }

   auto vec_data = std::vector<std::uint8_t>();
   vec_data.insert(vec_data.end(),
                   std::istreambuf_iterator<char>(fp),
                   std::istreambuf_iterator<char>());

   return vec_data;
}

void validate_target(const std::vector<std::uint8_t> &target)
{
   auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER *>(target.data());

   // IMAGE_DOS_SIGNATURE is 0x5A4D (for "MZ")
   if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
   {
      std::cerr << "Error: target image has no valid DOS header." << std::endl;
      ExitProcess(PACKER_ERROR_INVALID_DOS_HEADER);
   }

   auto nt_header = reinterpret_cast<const IMAGE_NT_HEADERS *>(target.data() + dos_header->e_lfanew);

   // IMAGE_NT_SIGNATURE is 0x4550 (for "PE")
   if (nt_header->Signature != IMAGE_NT_SIGNATURE)
   {
      std::cerr << "Error: target image has no valid NT header." << std::endl;
      ExitProcess(PACKER_ERROR_INVALID_NT_HEADER);
   }

   // IMAGE_NT_OPTIONAL_HDR64_MAGIC is 0x020B
   if (nt_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
   {
      std::cerr << "Error: only 64-bit executables are supported for this example!" << std::endl;
      ExitProcess(PACKER_ERROR_NOT_64BIT);
   }
}

std::vector<std::uint8_t> load_resource(LPCSTR name, LPCSTR type)
{
   auto resource = FindResourceA(nullptr, name, type);

   if (resource == nullptr)
   {
      std::cerr << "Error: couldn't find resource." << std::endl;
      ExitProcess(PACKER_ERROR_RESOURCE_NOT_FOUND);
   }

   auto rsrc_size = SizeofResource(GetModuleHandleA(nullptr), resource);
   auto handle = LoadResource(nullptr, resource);

   if (handle == nullptr)
   {
      std::cerr << "Error: couldn't load resource." << std::endl;
      ExitProcess(PACKER_ERROR_LOAD_RESOURCE_FAILED);
   }

   auto byte_buffer = reinterpret_cast<std::uint8_t *>(LockResource(handle));

   return std::vector<std::uint8_t>(&byte_buffer[0], &byte_buffer[rsrc_size]);
}

template <typename T>
T align(T value, T alignment)
{
   auto result = value + ((value % alignment == 0) ? 0 : alignment - (value % alignment));
   return result;
}

std::vector<std::uint8_t> extract_minimal_headers(const std::vector<std::uint8_t> &target)
{
   auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER *>(target.data());
   auto nt_header = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(target.data() + dos_header->e_lfanew);
   auto section_table = reinterpret_cast<const IMAGE_SECTION_HEADER *>(
       reinterpret_cast<const std::uint8_t *>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader);

   // Create minimal headers
   MINIMAL_IMAGE_DOS_HEADER minimal_dos = {};
   minimal_dos.e_lfanew = dos_header->e_lfanew;

   MINIMAL_IMAGE_NT_HEADERS64 minimal_nt = {};
   minimal_nt.FileHeader.Machine = nt_header->FileHeader.Machine;
   minimal_nt.FileHeader.NumberOfSections = nt_header->FileHeader.NumberOfSections;
   minimal_nt.FileHeader.SizeOfOptionalHeader = nt_header->FileHeader.SizeOfOptionalHeader;
   minimal_nt.FileHeader.Characteristics = nt_header->FileHeader.Characteristics;

   minimal_nt.OptionalHeader.Magic = nt_header->OptionalHeader.Magic;
   minimal_nt.OptionalHeader.AddressOfEntryPoint = nt_header->OptionalHeader.AddressOfEntryPoint;
   minimal_nt.OptionalHeader.ImageBase = nt_header->OptionalHeader.ImageBase;
   minimal_nt.OptionalHeader.SectionAlignment = nt_header->OptionalHeader.SectionAlignment;
   minimal_nt.OptionalHeader.FileAlignment = nt_header->OptionalHeader.FileAlignment;
   minimal_nt.OptionalHeader.SizeOfImage = nt_header->OptionalHeader.SizeOfImage;
   minimal_nt.OptionalHeader.SizeOfHeaders = nt_header->OptionalHeader.SizeOfHeaders;
   minimal_nt.OptionalHeader.Subsystem = nt_header->OptionalHeader.Subsystem;
   minimal_nt.OptionalHeader.DllCharacteristics = nt_header->OptionalHeader.DllCharacteristics;

   // Copy data directories we care about
   memcpy(&minimal_nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
          &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
          sizeof(MINIMAL_IMAGE_DATA_DIRECTORY));
   memcpy(&minimal_nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC],
          &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC],
          sizeof(MINIMAL_IMAGE_DATA_DIRECTORY));

   // Create minimal section headers
   std::vector<MINIMAL_IMAGE_SECTION_HEADER> minimal_sections(nt_header->FileHeader.NumberOfSections);
   for (WORD i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
   {
      memcpy(minimal_sections[i].Name, section_table[i].Name, IMAGE_SIZEOF_SHORT_NAME);
      minimal_sections[i].VirtualSize = section_table[i].Misc.VirtualSize;
      minimal_sections[i].VirtualAddress = section_table[i].VirtualAddress;
      minimal_sections[i].SizeOfRawData = section_table[i].SizeOfRawData;
      minimal_sections[i].PointerToRawData = section_table[i].PointerToRawData;
      minimal_sections[i].Characteristics = section_table[i].Characteristics;
   }

   // Serialize minimal headers into a buffer
   std::vector<std::uint8_t> buffer;
   buffer.reserve(sizeof(MINIMAL_IMAGE_DOS_HEADER) +
                  sizeof(MINIMAL_IMAGE_NT_HEADERS64) +
                  sizeof(MINIMAL_IMAGE_SECTION_HEADER) * minimal_sections.size());

   // Add DOS header
   buffer.insert(buffer.end(),
                 reinterpret_cast<std::uint8_t *>(&minimal_dos),
                 reinterpret_cast<std::uint8_t *>(&minimal_dos) + sizeof(MINIMAL_IMAGE_DOS_HEADER));

   // Add NT headers
   buffer.insert(buffer.end(),
                 reinterpret_cast<std::uint8_t *>(&minimal_nt),
                 reinterpret_cast<std::uint8_t *>(&minimal_nt) + sizeof(MINIMAL_IMAGE_NT_HEADERS64));

   // Add section headers
   buffer.insert(buffer.end(),
                 reinterpret_cast<std::uint8_t *>(minimal_sections.data()),
                 reinterpret_cast<std::uint8_t *>(minimal_sections.data() + minimal_sections.size()));

   return buffer;
}

int main(int argc, char *argv[])
{
   // read the file to pack
   auto target = read_file("C:\\Users\\sonx\\projects\\CTFs\\KMACTF-2025\\bf\\x64\\Release\\bf.exe");

   // validate that this is a PE file we can pack
   validate_target(target);

   // Extract minimal headers
   auto minimal_headers = extract_minimal_headers(target);

   // Get PE headers and section information
   auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(target.data());
   auto nt_header = reinterpret_cast<IMAGE_NT_HEADERS64 *>(target.data() + dos_header->e_lfanew);
   auto section_table = reinterpret_cast<IMAGE_SECTION_HEADER *>(
       reinterpret_cast<std::uint8_t *>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader);

   // Create a buffer containing only the PE sections
   std::vector<std::uint8_t> sections_data;
   for (WORD i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
   {
      if (section_table[i].SizeOfRawData > 0)
      {
         sections_data.insert(sections_data.end(),
                              target.data() + section_table[i].PointerToRawData,
                              target.data() + section_table[i].PointerToRawData + section_table[i].SizeOfRawData);
      }
   }

   // Create compressor
   COMPRESSOR_HANDLE compressor = NULL;
   if (!CreateCompressor(COMPRESS_ALGORITHM_MSZIP, NULL, &compressor))
   {
      std::cerr << "Error: couldn't create compressor. Error: " << GetLastError() << std::endl;
      ExitProcess(PACKER_ERROR_COMPRESS_FAILED);
   }

   // Get compressed size for minimal headers
   SIZE_T headers_compressed_size = 0;
   if (!Compress(compressor, minimal_headers.data(), minimal_headers.size(), NULL, 0, &headers_compressed_size))
   {
      DWORD error = GetLastError();
      if (error != ERROR_INSUFFICIENT_BUFFER)
      {
         std::cerr << "Error: failed to get compressed size for headers. Error: " << error << std::endl;
         CloseCompressor(compressor);
         ExitProcess(PACKER_ERROR_COMPRESS_FAILED);
      }
   }

   // Compress minimal headers
   std::vector<std::uint8_t> packed_headers(headers_compressed_size);
   if (!Compress(compressor, minimal_headers.data(), minimal_headers.size(),
                 packed_headers.data(), headers_compressed_size, &headers_compressed_size))
   {
      std::cerr << "Error: failed to compress headers. Error: " << GetLastError() << std::endl;
      CloseCompressor(compressor);
      ExitProcess(PACKER_ERROR_COMPRESS_FAILED);
   }

   // Get compressed size for sections
   SIZE_T sections_compressed_size = 0;
   if (!Compress(compressor, sections_data.data(), sections_data.size(), NULL, 0, &sections_compressed_size))
   {
      DWORD error = GetLastError();
      if (error != ERROR_INSUFFICIENT_BUFFER)
      {
         std::cerr << "Error: failed to get compressed size for sections. Error: " << error << std::endl;
         CloseCompressor(compressor);
         ExitProcess(PACKER_ERROR_COMPRESS_FAILED);
      }
   }

   // Compress sections
   std::vector<std::uint8_t> packed_sections(sections_compressed_size);
   if (!Compress(compressor, sections_data.data(), sections_data.size(),
                 packed_sections.data(), sections_compressed_size, &sections_compressed_size))
   {
      std::cerr << "Error: failed to compress sections. Error: " << GetLastError() << std::endl;
      CloseCompressor(compressor);
      ExitProcess(PACKER_ERROR_COMPRESS_FAILED);
   }

   CloseCompressor(compressor);

   // resize the buffers to their real compressed sizes
   packed_headers.resize(headers_compressed_size);
   packed_sections.resize(sections_compressed_size);

   // next, load the stub and get some initial information
   std::vector<std::uint8_t> stub_data = read_file("C:\\Users\\sonx\\projects\\packer\\stub\\x64\\Release\\stub.exe");

   // Get stub headers
   auto stub_dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(stub_data.data());
   auto stub_nt_header = reinterpret_cast<IMAGE_NT_HEADERS64 *>(stub_data.data() + stub_dos_header->e_lfanew);
   auto stub_section_table = reinterpret_cast<IMAGE_SECTION_HEADER *>(
       reinterpret_cast<std::uint8_t *>(&stub_nt_header->OptionalHeader) + stub_nt_header->FileHeader.SizeOfOptionalHeader);

   // Get alignment information
   auto file_alignment = stub_nt_header->OptionalHeader.FileAlignment;
   auto section_alignment = stub_nt_header->OptionalHeader.SectionAlignment;

   // align the buffer to the file boundary if it isn't already
   if (stub_data.size() % file_alignment != 0)
      stub_data.resize(align<std::size_t>(stub_data.size(), file_alignment));

   // save the offset to our new sections for later
   auto headers_raw_offset = static_cast<std::uint32_t>(stub_data.size());

   // encode the size of our unpacked headers into the stub data
   auto headers_unpacked_size = minimal_headers.size();
   stub_data.insert(stub_data.end(),
                    reinterpret_cast<std::uint8_t *>(&headers_unpacked_size),
                    reinterpret_cast<std::uint8_t *>(&headers_unpacked_size) + sizeof(std::size_t));

   // add our compressed headers
   stub_data.insert(stub_data.end(), packed_headers.begin(), packed_headers.end());

   // align after headers section
   if (stub_data.size() % file_alignment != 0)
      stub_data.resize(align<std::size_t>(stub_data.size(), file_alignment));

   // save the offset to our target section
   auto target_raw_offset = static_cast<std::uint32_t>(stub_data.size());

   // encode the size of our unpacked sections into the stub data
   auto sections_unpacked_size = sections_data.size();
   stub_data.insert(stub_data.end(),
                    reinterpret_cast<std::uint8_t *>(&sections_unpacked_size),
                    reinterpret_cast<std::uint8_t *>(&sections_unpacked_size) + sizeof(std::size_t));

   // add our compressed sections
   stub_data.insert(stub_data.end(), packed_sections.begin(), packed_sections.end());

   // calculate the section sizes
   auto headers_section_size = static_cast<std::uint32_t>(packed_headers.size() + sizeof(std::size_t));
   auto target_section_size = static_cast<std::uint32_t>(packed_sections.size() + sizeof(std::size_t));

   // re-acquire an NT header pointer since our buffer likely changed addresses
   stub_nt_header = reinterpret_cast<IMAGE_NT_HEADERS64 *>(stub_data.data() + stub_dos_header->e_lfanew);
   stub_section_table = reinterpret_cast<IMAGE_SECTION_HEADER *>(
       reinterpret_cast<std::uint8_t *>(&stub_nt_header->OptionalHeader) + stub_nt_header->FileHeader.SizeOfOptionalHeader);

   // pad the section data with 0s if we aren't on the file alignment boundary
   if (stub_data.size() % file_alignment != 0)
      stub_data.resize(align<std::size_t>(stub_data.size(), file_alignment));

   // increment the number of sections in the file header
   auto section_index = stub_nt_header->FileHeader.NumberOfSections;
   stub_nt_header->FileHeader.NumberOfSections += 2; // Add two new sections

   // get pointers to our new sections and the previous section
   auto headers_section = &stub_section_table[section_index];
   auto target_section = &stub_section_table[section_index + 1];
   auto prev_section = &stub_section_table[section_index - 1];

   // calculate the memory offsets, memory sizes and raw aligned sizes
   auto headers_virtual_offset = align(prev_section->VirtualAddress + prev_section->Misc.VirtualSize, section_alignment);
   auto target_virtual_offset = align(headers_virtual_offset + headers_section_size, section_alignment);
   auto headers_raw_size = align<DWORD>(headers_section_size, file_alignment);
   auto target_raw_size = align<DWORD>(target_section_size, file_alignment);

   // assign the headers section metadata
   std::memcpy(headers_section->Name, ".pack0", 7);
   headers_section->Misc.VirtualSize = headers_section_size;
   headers_section->VirtualAddress = headers_virtual_offset;
   headers_section->SizeOfRawData = headers_raw_size;
   headers_section->PointerToRawData = headers_raw_offset;
   headers_section->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

   // assign the target section metadata
   std::memcpy(target_section->Name, ".pack1", 7);
   target_section->Misc.VirtualSize = target_section_size;
   target_section->VirtualAddress = target_virtual_offset;
   target_section->SizeOfRawData = target_raw_size;
   target_section->PointerToRawData = target_raw_offset;
   target_section->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

   // calculate the new size of the image
   stub_nt_header->OptionalHeader.SizeOfImage = align(target_virtual_offset + target_section_size, section_alignment);

   std::ofstream fp("C:\\Users\\sonx\\projects\\packer\\packer\\x64\\Release\\packed.exe", std::ios::binary);

   if (!fp.is_open())
   {
      std::cerr << "Error: couldn't open packed binary for writing." << std::endl;
      ExitProcess(PACKER_ERROR_WRITE_FAILED);
   }

   fp.write(reinterpret_cast<const char *>(stub_data.data()), stub_data.size());
   fp.close();

   std::cout << "File successfully packed." << std::endl;

   return 0;
}