#pragma once
#include <windows.h>
#include <stdint.h>

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME 8

// --- Minimal IMAGE_FILE_HEADER ---
typedef struct _MINIMAL_IMAGE_FILE_HEADER
{
    WORD Machine;
    WORD NumberOfSections;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} MINIMAL_IMAGE_FILE_HEADER, *PMINIMAL_IMAGE_FILE_HEADER;

// --- Minimal IMAGE_DATA_DIRECTORY ---
typedef struct _MINIMAL_IMAGE_DATA_DIRECTORY
{
    DWORD VirtualAddress;
    DWORD Size;
} MINIMAL_IMAGE_DATA_DIRECTORY, *PMINIMAL_IMAGE_DATA_DIRECTORY;

// --- Minimal IMAGE_OPTIONAL_HEADER64 ---
typedef struct _MINIMAL_IMAGE_OPTIONAL_HEADER64
{
    WORD Magic;                // Must be 0x20B for PE32+
    DWORD AddressOfEntryPoint; // RVA to entry
    ULONGLONG ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    WORD Subsystem;
    WORD DllCharacteristics;
    MINIMAL_IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} MINIMAL_IMAGE_OPTIONAL_HEADER64, *PMINIMAL_IMAGE_OPTIONAL_HEADER64;

// --- Minimal IMAGE_DOS_HEADER --
typedef struct _MINIMAL_IMAGE_DOS_HEADER
{
    LONG e_lfanew;
} MINIMAL_IMAGE_DOS_HEADER, *PMINIMAL_IMAGE_DOS_HEADER;

// --- Minimal IMAGE_NT_HEADERS64 ---
typedef struct _MINIMAL_IMAGE_NT_HEADERS64
{
    MINIMAL_IMAGE_FILE_HEADER FileHeader;
    MINIMAL_IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} MINIMAL_IMAGE_NT_HEADERS64, *PMINIMAL_IMAGE_NT_HEADERS64;

// --- Minimal IMAGE_SECTION_HEADER ---
typedef struct _MINIMAL_IMAGE_SECTION_HEADER
{
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME]; // Optional, mostly cosmetic
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD Characteristics;
} MINIMAL_IMAGE_SECTION_HEADER, *PMINIMAL_IMAGE_SECTION_HEADER;
