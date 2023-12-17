

#include <stdio.h>
#include <windows.h>



void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved);
int newstrcmp(const char* s1, const char* s2);
void shiftRows(byte** array, int cols, int rows);
void shiftColumns(byte** array, int cols, int rows);
void swapHex(byte** array, int cols, int rows);
void xorArr(byte** array, int cols, int rows, int key);
char* extractSubstring(const char* str);
bool isCorrect(byte** array, int cols, int rows);



// _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
EXTERN_C
#pragma data_seg (".CRT$XLB")

PIMAGE_TLS_CALLBACK _tls_callback = TLSCallbacks;
#pragma data_seg ()
#pragma const_seg ()





void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
	int (*functionPointer)(const char*, const char*);
	DWORD oldProtection;
	size_t size;
	bool result;
	LPVOID addrDestFunc;

	if (IsDebuggerPresent()) return;

	addrDestFunc = (LPVOID)&newstrcmp;
	unsigned char asmCode[] = {
			0x68, 0x00, 0x00, 0x00, 0x00,
			0xC3
	};
	memcpy(asmCode + 1, &addrDestFunc, 4);
	size = sizeof(asmCode);
	functionPointer = &strcmp;
	result = VirtualProtect(functionPointer, size, PAGE_EXECUTE_READWRITE, &oldProtection);
	CopyMemory(functionPointer, asmCode, size);

	return;
}



int newstrcmp(const char* s1, const char* s2) {
	char key[32] = { 7, 124, 0, 7, 127, 119, 120, 1, 0, 115, 7, 117, 0, 2, 3, 115, 7, 7, 0, 12, 7, 114, 123, 112, 4, 127, 3, 4, 7, 113, 0, 4 };
	char dest[36];
	memset(dest, 0, sizeof(dest));
	for(int i = 0; i < sizeof(key); i++) {
		dest[i] = s2[i] ^ key[i];
	}
	int length = strlen(dest);
	for (size_t i = 0; i < length; i++)
	{
		if (s1[i] < dest[i]) return -1;
		else if (s1[i] > dest[i]) return 1;
	}
	return 0;
}


void shiftRows(byte** array, int cols, int rows) {
	byte* temp = (byte*)malloc(cols * sizeof(byte));
	for (int i = 0; i < rows; i++) {
		memcpy(temp, array[i], sizeof(array[i]));
		for (int j = 0; j < cols; j++) {
			array[i][j] = temp[(j + i) % 4];
		}
	}
	free(temp);
}

void shiftColumns(byte** array, int cols, int rows) {
	byte* temp = (byte*)malloc(rows * sizeof(byte));
	for (int i = 0; i < cols; i++) {
		for (int j = 0; j < rows; j++) {
			temp[j] = array[j][i];
		}
		for (int j = 0; j < rows; j++) {
			array[j][i] = temp[(j + i) % 4];
		}
	}
	free(temp);
}

void swapHex(byte** array, int cols, int rows) {
	byte temp;
	for (int i = 0; i < rows; i++) {
		for (int j = 0; j < cols; j++) {
			temp = array[i][j];
			array[i][j] = (temp / 16) + (temp % 16) * 16;
		}
	}
}

void xorArr(byte** array, int cols, int rows, int key) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			array[i][j] = array[i][j] ^ key;
		}
	}
}



char* extractSubstring(const char* str) {
	const char* start = strstr(str, "KCSC{");
	if (start != NULL) {
		start += strlen("KCSC{");

		const char* end = strchr(start, '}');
		if (end != NULL) {
			size_t length = end - start;

			char* result = (char*)malloc((length + 1) * sizeof(char));
			if (strncpy_s(result, length + 1, start, length) == 0) {
				return result;
			}
			else {
				free(result);
			}
		}
	}
	return NULL;
}


bool isCorrect(byte** array, int cols, int rows) {
	char temp[3];
	char hexString[48];
	memset(hexString, 0, sizeof(hexString));

	for (int i = 0; i < rows; ++i) {
		for (int j = 0; j < cols; ++j) {
			sprintf_s(temp, 3, "%02X", array[i][j]);
			hexString[2 * (i * cols + j)] = temp[0];
			hexString[2 * (i * cols + j) + 1] = temp[1];
		}
	}	
	return (strcmp(hexString, "FDA6FF91ADA0FDB7ABA9FB91EFAFFAA2") == 0) ? true : false;
}

void printArray(byte** array, int cols, int rows) {
	for (int i = 0; i < rows; i++) {
		for (int j = 0; j < cols; j++) {
			printf("%d ", array[i][j]);
		}
		printf("\n");
	}
	printf("\n");
}



int main(int argc, char* argv[])
{
	char input[32];
	char* data;
	int cols = 4;
	int rows = 4;
	byte** array = (byte**)malloc(rows * sizeof(byte*));
	for (int i = 0; i < rows; ++i) {
		array[i] = (byte*)malloc(cols * sizeof(byte));
	}

	memset(input, 0, 32);
	printf("Show your skills. What is the flag?\n");
	fgets(input, 32, stdin);
	
	if (input[strlen(input) - 1] == '\n')
		input[strlen(input) - 1] = '\0';

	if (strlen(input) != 22) goto wrong;

	data = extractSubstring(input);

	if ((data != NULL) && (strlen(data) == 16)) {
		for (int i = 0; i < rows; i++) {
			for (int j = 0; j < cols; j++) {
				array[i][j] = data[i * 4 + j];
			}
		}
		for (int k = 0; k < 100; k++) {
			shiftRows(array, cols, rows);
			shiftColumns(array, cols, rows);
			swapHex(array, cols, rows);
			xorArr(array, cols, rows, 0x55 + k);
		}
		//printArray(array, cols, rows);
		if (isCorrect(array, cols, rows))
			goto correct;
		else
			goto wrong;
	}
	else {
		goto wrong;
	}


wrong:
	printf("Wrong flag! You chicken");
	free(array);
	return 0;

correct:
	printf("Good. Nice work");
	free(array);
	return 0;
}