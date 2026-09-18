import socket
import subprocess
import time
import hashlib
import os
import sys

def main():
    print("[Test] Starting automated end-to-end tunnel test...")

    # Port allocation
    TARGET_PORT = 19010
    SERVER_PORT = 19011
    CLIENT_PORT = 19012
    KEY = "livekadeh_secret_passphrase_test_2026"

    # Step 1: Start Mock Echo Server on TARGET_PORT
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", TARGET_PORT))
    server_sock.listen(5)
    server_sock.settimeout(10.0)

    # Step 2: Start livekadeh server
    p_server = subprocess.Popen([
        "/root/test_project/livekadeh_tunnel/build/livekadeh", "server",
        "-l", f"127.0.0.1:{SERVER_PORT}",
        "-t", f"127.0.0.1:{TARGET_PORT}",
        "-k", KEY
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Step 3: Start livekadeh client
    p_client = subprocess.Popen([
        "/root/test_project/livekadeh_tunnel/build/livekadeh", "client",
        "-l", f"127.0.0.1:{CLIENT_PORT}",
        "-s", f"127.0.0.1:{SERVER_PORT}",
        "-k", KEY
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    time.sleep(1)

    try:
        # Step 4: Connect to CLIENT_PORT and simulate an SSH connection & binary data transfer
        test_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_client.connect(("127.0.0.1", CLIENT_PORT))

        # Accept on mock server
        mock_conn, addr = server_sock.accept()

        # Generate 1MB of random data
        payload = os.urandom(1024 * 1024)
        expected_hash = hashlib.sha256(payload).hexdigest()

        # Send from client -> tunnel -> mock server
        test_client.sendall(payload)

        received = bytearray()
        while len(received) < len(payload):
            chunk = mock_conn.recv(65536)
            if not chunk:
                break
            received.extend(chunk)

        actual_hash = hashlib.sha256(received).hexdigest()
        assert actual_hash == expected_hash, f"Hash mismatch! {actual_hash} != {expected_hash}"
        print(f"[Success] 1MB payload successfully tunneled C->S with SHA-256 match: {actual_hash}")

        # Send back from mock server -> tunnel -> client (Reverse direction)
        mock_conn.sendall(payload)

        received_back = bytearray()
        while len(received_back) < len(payload):
            chunk = test_client.recv(65536)
            if not chunk:
                break
            received_back.extend(chunk)

        actual_back_hash = hashlib.sha256(received_back).hexdigest()
        assert actual_back_hash == expected_hash, f"Hash mismatch in reverse! {actual_back_hash} != {expected_hash}"
        print(f"[Success] 1MB payload successfully tunneled S->C with SHA-256 match: {actual_back_hash}")

        # Test simulated SSH banner
        ssh_banner = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4\r\n"
        mock_conn.sendall(ssh_banner)
        received_banner = test_client.recv(len(ssh_banner))
        assert received_banner == ssh_banner
        print("[Success] SSH protocol banner successfully transmitted bidirectional!")

        test_client.close()
        mock_conn.close()

    finally:
        p_client.terminate()
        p_server.terminate()
        server_sock.close()

    print("[All Tests Passed Successfully!]")

if __name__ == "__main__":
    main()

