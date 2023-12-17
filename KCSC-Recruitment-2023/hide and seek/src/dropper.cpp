

#include <iostream>
#include "resource.h"
#include <windows.h>
#include <vector>
#include <tchar.h>

#define GETTEMPPATHW 0x5ea58ccd7eb77
constexpr auto MAX_PATH_LEN = 256;

TCHAR filepath[MAX_PATH_LEN];

HMODULE GCM() {
	HMODULE hModule = NULL;
	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)GCM, &hModule);
	return hModule;
}

BOOL WriteResourceToFile(HMODULE hModule, LPCTSTR lpName, LPCTSTR lpType) {
	LPCTSTR lpFilePath = (LPCTSTR)filepath;

	HRSRC hRes = FindResource(hModule, lpName, lpType);
	if (!hRes) {
		std::cerr << "Failed to find resource" << std::endl;
		return FALSE;
	}

	HGLOBAL hResLoad = LoadResource(hModule, hRes);
	if (!hResLoad) {
		std::cerr << "Failed to load resource" << std::endl;
		return FALSE;
	}

	LPVOID lpResLock = LockResource(hResLoad);
	if (!lpResLock) {
		std::cerr << "Failed to lock resource" << std::endl;
		return FALSE;
	}

	DWORD dwSize = SizeofResource(hModule, hRes);
	HANDLE hFile = CreateFile(lpFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to create file" << std::endl;
		return FALSE;
	}

	DWORD dwWritten = 0;
	BOOL bWriteOK = WriteFile(hFile, lpResLock, dwSize, &dwWritten, NULL);
	if (!bWriteOK || dwSize != dwWritten) {
		std::cerr << "Failed to write file" << std::endl;
		return FALSE;
	}

	CloseHandle(hFile);

	return TRUE;
}



__int64 GetHashFromString(char* string)
{
	size_t stringLength = strnlen_s(string, 50);
	__int64 hash = 0xab5248ed;

	for (size_t i = 0; i < stringLength; i++)
	{
		hash += (hash * 0x3901abdef69220c3 + string[i]) & 0xffffffffffff;
	}
	return hash;
}

PDWORD GetFunctionAddressByHash(char* library, __int64 hash)
{
	PDWORD functionAddress = NULL;

	// Get base address of the module in which our exported function of interest resides (kernel32 in the case of CreateThread)
	HMODULE libraryBase = LoadLibraryA(library);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = NULL;
	imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	// Get RVAs to exported function related information
	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	// Iterate through exported functions, calculate their hashes and check if any of them match the hash
	// If yes, get its virtual memory address
	for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
	{
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		DWORD_PTR functionAddressRVA = 0;

		// Calculate hash for this exported function
		__int64 functionNameHash = GetHashFromString(functionName);

		// If hash for CreateThread is found, resolve the function address
		if (functionNameHash == hash)
		{
			functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
			functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
			return functionAddress;
		}
	}

	std::cerr << "Failed to find function address" << std::endl;
	return NULL;
}

using MyGetTempPathW = DWORD(NTAPI*) (
	DWORD nBufferLength,
	LPWSTR lpBuffer
	);


bool FindDestination() {
	TCHAR tempFolderPath[MAX_PATH_LEN];
	MyGetTempPathW getTempPathW = (MyGetTempPathW)GetFunctionAddressByHash((char*)("kernel32"), GETTEMPPATHW);

	if (!getTempPathW) {
		return 0;
	}

	// Get the temp folder path
	DWORD dwRetVal = getTempPathW(MAX_PATH_LEN, tempFolderPath);
	if (dwRetVal > MAX_PATH_LEN || (dwRetVal == 0)) {
		std::cerr << "Failed to get folder path" << std::endl;
		return 0;
	}
	wsprintfW(filepath, L"%s\x202Etemp_html_file_%u.html", tempFolderPath, GetTickCount64());
	return 1;
}


std::string GetCurrentUserName() {
	DWORD size = 0;
	// First call to get the size of the username
	GetUserNameW(NULL, &size);

	if (!size) return "player";

	// Allocate a buffer of the correct size
	std::vector<wchar_t> username(size);
	// Actual call to get the username
	if (GetUserNameW(username.data(), &size)) return std::string(username.begin(), username.end());
	else return "player";
}

void ShowWarning() {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hConsole != INVALID_HANDLE_VALUE) {
		// Save current attributes
		CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
		GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
		WORD saved_attributes = consoleInfo.wAttributes;
		// Show loading screen \ | / -
		char loading[4] = { '\\', '|', '/', '-' };
		for (int i = 0; i < 20; i++) {
			std::cout << "Loading " << loading[i % 4] << "\r";
			Sleep(50);
		}

		// Change text color to black
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
		std::cout << " _   __      __ ___  ___  _  _  ___  _  _   ___   _			" << std::endl;
		std::cout << "| |  \\ \\    / //   \\| _ \\| \\| ||_ _|| \\| | / __| | |	" << std::endl;
		std::cout << "|_|   \\ \\/\\/ / | - ||   /| .  | | | | .  || (_ | |_|		" << std::endl;
		std::cout << "(_)    \\_/\\_/  |_|_||_|_\\|_|\\_||___||_|\\_| \\___| (_)	" << std::endl;
		std::cout << "																" << std::endl;

		SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
		std::string message_1 = "Dear, " + GetCurrentUserName() + "\n";
		std::string message_2 = "A mysterious file has been placed on your computer. \nFind it at the following location: \n";
		for (char c : message_1) {
			std::cout << c;
			Sleep(50);
		}

		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		for (char c : message_2) {
			std::cout << c;
			Sleep(50);
		}

		SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | BACKGROUND_BLUE);
		for (char c : filepath) {
			std::cout << c;
			Sleep(50);
		}

		std::cout << std::endl;


		// Restore original attributes
		SetConsoleTextAttribute(hConsole, saved_attributes);
	}

}



int main() {
	if (!FindDestination()) {
		std::cerr << "Stage 1 failed" << std::endl;
		return 1;
	}
	if (!WriteResourceToFile(GCM(), MAKEINTRESOURCE(IDR_HTML1), MAKEINTRESOURCE(HTML))) {
		std::cerr << "Stage 2 failed" << std::endl;
		return 1;
	}
	ShowWarning();

	return 0;
}



