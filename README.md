
# XOR Encrypt Utility

`Xor_encode` is a simple C-based XOR encryption utility designed for encoding shellcode and wide character strings (e.g., file paths) with a single-byte XOR key. It is primarily intended for use in red team operations, malware development research, or security-related toolchains where obfuscation of binary payloads is required.

---

## Features

- XOR-encrypts raw byte arrays (e.g., shellcode)
- XOR-encrypts wide character strings (`wchar_t[]`)
- Prints output in clean C-style format suitable for direct inclusion in source code
- Customizable XOR key (`0x5A` by default)
- Minimal, fast, and dependency-free

---

## Use Cases

- Shellcode obfuscation for bypassing basic static signature detection
- Encoding payloads or strings for Windows API-based injection
- Generating encrypted resources for use in loaders or droppers
- Demonstrating XOR operations in educational or CTF contexts

---

## How It Works

The program takes:
- A **hardcoded byte array** (representing shellcode)
- A **hardcoded wide string** (e.g., `L"C:\\Windows\\System32\\notepad.exe"`)

It then:
1. XOR-encrypts the data using a key (`0x5A` by default)
2. Outputs the result as a valid C-style array:
   - `const unsigned char EncryptedShellcode[] = {...};`
   - `const WCHAR EncryptedTargetPath[] = {...};`

---

## Compilation

Use `gcc` or any modern C compiler. For example:

```bash
gcc xor_encode.c -o xor_encode
````

> On Windows, you may want to compile with `cl.exe` or MinGW:

```bash
cl xor_encode.c
```

---

## Sample Output

Running the binary will produce two outputs:

1. **Encrypted Shellcode**

```c
const unsigned char EncryptedShellcode[] = {
    0xA6, 0x12, 0xD9, 0xBE, 0xAA, 0xB2, 0x9A, 0x5A, ...
};
```

2. **Encrypted Wide String Path**

```c
const WCHAR EncryptedTargetPath[] = {
    0x1909, 0x1B30, 0x1B30, 0x1B32, ...
};
```

You can copy these arrays directly into a C project and decrypt them at runtime using the same XOR key.

---

## XOR Key

By default, the XOR key is:

```c
#define XOR_KEY 0x5A
```

You can change this value to anything between `0x00` and `0xFF` as needed.

---

## Functions Breakdown

### `XorEncryptBytes()`

Encrypts a byte array (e.g., shellcode)

### `XorEncryptWString()`

Encrypts a `wchar_t[]` wide string (e.g., Windows paths)

### `PrintByteArray()`

Formats and prints the result as `unsigned char[]`

### `PrintWCharArray()`

Formats and prints the result as `WCHAR[]`

---

## Example Use Case

Injecting encrypted shellcode into a remote process:

1. Encode shellcode using this utility.
2. Copy output into your loader C code.
3. Decrypt at runtime before execution.

---

## Disclaimer

This tool is intended for **educational and authorized security research purposes only**. Do not use it to target systems or networks without explicit permission. Unauthorized use is illegal and unethical.

---

## License

Free to use and modify under the MIT License.

