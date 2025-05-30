XOR Encryption Utility
Overview
This C program is a utility designed to encrypt shellcode and wide strings (e.g., file paths) using a simple XOR encryption algorithm. It is intended for security researchers working on projects like process hollowing to evade static analysis by Endpoint Detection and Response (EDR) systems. The program takes input data (shellcode or strings), applies XOR encryption with a specified key, and outputs the encrypted data as C-style arrays for integration into other projects.
Features

Shellcode Encryption: Encrypts raw shellcode (e.g., calculator shellcode) using an XOR key.
Wide String Encryption: Encrypts wide-character strings (e.g., target process paths like C:\Windows\System32\notepad.exe).
C-Style Output: Generates formatted C arrays (unsigned char for shellcode, WCHAR for strings) for easy inclusion in other C programs.
Error Handling: Includes memory allocation checks to ensure robustness.
Customizable XOR Key: Uses a predefined XOR key (0x5A) that can be modified as needed.

Prerequisites

A C compiler (e.g., MSVC, gcc).
Windows environment (for wchar.h and wide string support).
Basic understanding of shellcode and C programming.

Usage
Compilation
Compile the program using a C compiler. Examples:

MSVC: cl xor_encrypt.c
gcc: gcc xor_encrypt.c -o xor_encrypt

Input
The program includes example inputs:

Shellcode: A sample shellcode (replace with your full shellcode, e.g., RawX64CalcShellcode).
Target Path: A wide string (L"C:\\Windows\\System32\\notepad.exe") representing a target process path.

To use your own data:

Replace the shellcode array in main() with your shellcode.
Modify the targetPath string if you need to encrypt a different path.
Optionally, change the XOR_KEY (0x5A) to a different value.

Running the Program
Execute the compiled program:
./xor_encrypt

The program will:

Encrypt the shellcode and target path using the XOR key.
Output two C-style arrays:
EncryptedShellcode: The XOR-encrypted shellcode.
EncryptedTargetPath: The XOR-encrypted target process path.



Example Output
[+] Encrypted shellcode:
const unsigned char EncryptedShellcode[] = {
    0xA6, 0x12, 0xD9, 0xBE, 0xAA, 0xB2, 0x9A, 0x5A, 0x5A, 0x5A, 0x1B, 0x0B,
    // ... (continues for the full shellcode)
};

[+] Encrypted target path:
const WCHAR EncryptedTargetPath[] = {
    0x0076, 0x002F, 0x003E, 0x003E, 0x0057, 0x0070, 0x003A, 0x006E, 0x0067, 0x006F,
    0x0073, 0x003E, 0x003E, 0x003A, 0x0079, 0x0073, 0x0074, 0x0065, 0x006D, 0x0033,
    0x0032, 0x003E, 0x003E, 0x006E, 0x006F, 0x0074, 0x0065, 0x0070, 0x0061, 0x0064,
    0x002E, 0x0065, 0x0078, 0x0065, 0x0000
};

Integration
To use the encrypted output in your process hollowing project:

Copy the EncryptedShellcode array into your process hollowing code.
Copy the EncryptedTargetPath array into your process hollowing code.
Ensure the decryption functions in your process hollowing code (e.g., DecryptShellcode and DecryptString) use the same XOR_KEY (0x5A).

Code Structure

XorEncryptBytes: Encrypts a byte array (e.g., shellcode) using the XOR key.
XorEncryptWString: Encrypts a wide string using the XOR key.
PrintByteArray: Formats and prints a byte array as a C-style unsigned char array.
PrintWCharArray: Formats and prints a wide string as a C-style WCHAR array.
main: Orchestrates encryption and output, with example shellcode and target path.

Notes

Shellcode: The example shellcode is truncated. Replace it with your full shellcode to encrypt the entire payload.
XOR Key: The default key is 0x5A. For better evasion, consider using a random key or modifying it per build.
Evasion: This program helps evade static EDR scans by encrypting data. Ensure the decryption logic in your target program matches the encryption key and method.
Limitations: XOR encryption is simple and may not evade advanced EDRs with dynamic analysis. Consider more complex encryption (e.g., AES) for stronger evasion.

Testing

Verify the encrypted output by manually decrypting it (XOR with 0x5A) to ensure correctness.
Test the output arrays in your process hollowing program to confirm they decrypt and function correctly.
Use tools like PEiD or Detect It Easy to check if the compiled binary is flagged by static scanners.

Future Improvements

Add command-line arguments to specify input data or XOR key.
Support file input for shellcode or strings.
Implement more advanced encryption algorithms (e.g., AES) for better evasion.
Add random key generation for each run.

Legal and Ethical Considerations
This tool is for educational and research purposes only. Ensure compliance with all applicable laws and ethical guidelines when using this code, especially in security research involving EDR evasion or process injection.
