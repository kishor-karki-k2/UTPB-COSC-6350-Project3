import socket
from Crypto import *

# Constants
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555


def tcp_client():
    """Connect to server and receive/decrypt packets"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((SERVER_HOST, SERVER_PORT))
            print(f"[INFO] Connected to {SERVER_HOST}:{SERVER_PORT}")

            # Receive total packets count from server
            total_packets_str = client_socket.recv(1024).decode()
            total_packets = int(total_packets_str)
            client_socket.sendall(b'ACK')  # Acknowledge receipt of total packets

            successfully_decrypted = 0
            failed_attempts = {}
            received_packets = []
            last_progress_milestone = 0
            last_decrypted_message = ""

            print(f"[INFO] Expecting {total_packets} packets")

            while True:
                encrypted_packet = client_socket.recv(1024)
                if not encrypted_packet or encrypted_packet == b'END':
                    print("[INFO] End of transmission received.")
                    print("[INFO] Progress: 100% completed")
                    print(f"[INFO] Final decrypted message: {last_decrypted_message}")
                    break

                # Try decryption with each key
                key_attempts = list(keys.values())
                packet_number = successfully_decrypted  # Use successfully_decrypted as packet counter
                key_attempts_failed = failed_attempts.get(packet_number, [])

                decryption_successful = False
                for key in key_attempts:
                    if key in key_attempts_failed:
                        continue

                    try:
                        decrypted_message = aes_decrypt(encrypted_packet, key)
                        if decrypted_message == "The quick brown fox jumps over the lazy dog.":
                            client_socket.sendall(b'ACK')
                            successfully_decrypted += 1
                            received_packets.append(decrypted_message)
                            decryption_successful = True
                            last_decrypted_message = decrypted_message  # Store the last successful decryption

                            # Calculate current progress percentage based on total_packets
                            current_progress = (successfully_decrypted / total_packets) * 100

                            # Show progress at 25% intervals
                            if current_progress >= 25 and last_progress_milestone < 25:
                                print(
                                    f"\n[INFO] Progress: 25% completed ({successfully_decrypted}/{total_packets} packets)")
                                print(f"[INFO] Current decrypted message: {last_decrypted_message}")
                                last_progress_milestone = 25
                            elif current_progress >= 50 and last_progress_milestone < 50:
                                print(
                                    f"\n[INFO] Progress: 50% completed ({successfully_decrypted}/{total_packets} packets)")
                                print(f"[INFO] Current decrypted message: {last_decrypted_message}")
                                last_progress_milestone = 50
                            elif current_progress >= 75 and last_progress_milestone < 75:
                                print(
                                    f"\n[INFO] Progress: 75% completed ({successfully_decrypted}/{total_packets} packets)")
                                print(f"[INFO] Current decrypted message: {last_decrypted_message}")
                                last_progress_milestone = 75

                            break
                    except Exception:
                        key_attempts_failed.append(key)

                if not decryption_successful:
                    client_socket.sendall(b'NACK')
                    failed_attempts[packet_number] = key_attempts_failed

            print(f"\n[INFO] Successfully decrypted {successfully_decrypted}/{total_packets} packets.")
            print(f"[INFO] Final message successfully decrypted: {last_decrypted_message}")

        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            print("[INFO] Connection closed.")


if __name__ == "__main__":
    tcp_client()