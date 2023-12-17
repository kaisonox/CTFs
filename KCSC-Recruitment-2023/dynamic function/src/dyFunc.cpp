

#include <stdio.h>
#include <string.h>
#include <cstdlib>
#include <Windows.h>

const byte dataFunc[] = { 0X14, 0XC8, 0XA4, 0XC2, 0XAD, 0X61, 0X86, 0X4, 0XA3, 0X33, 0X24, 0X37, 0X24, 0X86, 0X4, 0XA7, 0X33, 0X32, 0X28, 0X2F, 0X86, 0X4, 0XAB, 0X26, 0X1E, 0X28, 0X32, 0X86, 0X4, 0XAF, 0X1E, 0X31, 0X33, 0X24, 0X86, 0X4, 0XB3, 0X35, 0X35, 0X38, 0X1E, 0X86, 0X4, 0XB7, 0X22, 0X2E, 0X2E, 0X2D, 0X87, 0X4, 0XBB, 0X41, 0X86, 0X4, 0XBD, 0X41, 0X41, 0X41, 0X41, 0XAA, 0X19, 0XCA, 0X14, 0XBD, 0XCA, 0X4, 0X49, 0X40, 0X91, 0X4E, 0XF7, 0X41, 0XC8, 0X83, 0X81, 0XBB, 0X46, 0X81, 0XAB, 0X45, 0X40, 0X91, 0XC2, 0XA1, 0X4E, 0X68, 0X91, 0X80, 0XA1, 0X45, 0XC8, 0X80, 0XCA, 0X14, 0XBD, 0XCA, 0X4, 0X49, 0X40, 0X91, 0X4E, 0XF7, 0X41, 0XC8, 0X83, 0X81, 0XBB, 0X46, 0X81, 0XAB, 0X45, 0X40, 0X91, 0X81, 0XB9, 0X45, 0X40, 0X89, 0XC9, 0X4, 0XBA, 0XCA, 0X14, 0XBD, 0XCA, 0X4, 0X4D, 0X40, 0X83, 0XCC, 0XC, 0XA3, 0XCA, 0X4, 0XBD, 0X40, 0X89, 0X4E, 0XF7, 0X41, 0X73, 0X4, 0XBA, 0XC9, 0X43, 0XC2, 0X4, 0XBD, 0X40, 0XCA, 0X4, 0XBD, 0X7A, 0X4, 0X51, 0X3D, 0XE1, 0XF9, 0X41, 0X41, 0X41, 0X41, 0X88, 0X82 };
const char dest[] = { 0x44, 0x93, 0x51, 0x42, 0x24, 0x45, 0x2E, 0x9B, 0x01, 0x99, 0x7F, 0x05, 0x4D, 0x47, 0x25, 0x43, 0xA2, 0xE2, 0x3E, 0xAA, 0x85, 0x99, 0x18, 0x7E };


int encryptString(char* str, char* result, int len) {
    char key[25] = "reversing_is_pretty_cool";
    char temp;
    for (int i = 0; i < len; i++) {
        temp = (str[i] % 16) * 16 + (str[i] / 16);
        result[i] = temp ^ key[i];
    }
    return 0;
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


int main() {
    char input[32];
	memset(input, 0, sizeof(input));
	char* data = (char*)malloc(25 * sizeof(char));
    char* result = (char*)malloc(25 * sizeof(char));
	int temp;
	char* mem = NULL;


	printf("Show your skills. What is the flag?\n");
	fgets(input, 32, stdin);

	if (input[strlen(input) - 1] == '\n')
		input[strlen(input) - 1] = '\0';

	if (strlen(input) != 30) goto wrong;

	data = extractSubstring(input);

	if ((data != NULL) && (strlen(data) == 24)) {
		mem = (char*)VirtualAlloc(NULL, sizeof(dataFunc), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (mem == NULL) {
			perror("VirtualAlloc failed");
			return 1;
		}
		for (int i = 0; i < sizeof(dataFunc); i++)
			mem[i] = (dataFunc[i] ^ 0x41);
		temp = ((int(__cdecl*)(char*, char*, int))(void*)mem)(data, result, strlen(data));
		VirtualFree(mem, sizeof(dataFunc), 0x8000u);

		for (int i = 0; i < strlen(data); i++) {
			if (result[i] != dest[i]) goto wrong;
		}

		goto correct;
	}


wrong:
	printf("Not correct @_@");
	return 0;
correct:
	printf("Not uncorrect ^_^");
    return 0;
}