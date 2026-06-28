#!/usr/bin/env python3
"""
stage2.py — Stage 2: Real-time IPC Classifier & Mitigation Engine
-----------------------------------------------------------------
Listens on the Unix Domain Socket at /tmp/ddos_stage1.sock for 88-byte feature
vectors containing window statistics and the dominant IP address.
Predicts traffic class (0: Normal, 1: Flash Crowd, 2: DDoS) in real-time
and triggers kernel-level mitigation via ipset for DDoS.
"""

import os
import sys
import socket
import struct
import ipaddress
import subprocess
import logging
import joblib

# Constants
SOCKET_PATH = "/tmp/ddos_stage1.sock"
MODEL_PATH = "ddos_rf_model.joblib"
FEATURE_VECTOR_FORMAT = "<9d16s"  # 9 x f64 (72 bytes) + 16-byte IP address = 88 bytes
PAYLOAD_SIZE = struct.calcsize(FEATURE_VECTOR_FORMAT)

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] stage2: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("stage2.log", mode="a")
    ]
)

def setup_ipset():
    """Ensure the target ipset list exists and is linked to iptables rules."""
    try:
        # Create hash:ip set if it doesn't exist
        subprocess.run(
            ["ipset", "create", "ddos_blocklist", "hash:ip", "timeout", "3600"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        logging.info("[+] Kernel ipset 'ddos_blocklist' verified/created (timeout = 3600s).")

        # Link ipset to iptables INPUT chain if not already present
        check_input = subprocess.run(
            ["iptables", "-C", "INPUT", "-m", "set", "--match-set", "ddos_blocklist", "src", "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if check_input.returncode != 0:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-m", "set", "--match-set", "ddos_blocklist", "src", "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            logging.info("[+] Linked 'ddos_blocklist' to iptables INPUT chain.")
            
        # Link ipset to iptables FORWARD chain if not already present
        check_forward = subprocess.run(
            ["iptables", "-C", "FORWARD", "-m", "set", "--match-set", "ddos_blocklist", "src", "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if check_forward.returncode != 0:
            subprocess.run(
                ["iptables", "-I", "FORWARD", "-m", "set", "--match-set", "ddos_blocklist", "src", "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            logging.info("[+] Linked 'ddos_blocklist' to iptables FORWARD chain.")

    except Exception as e:
        logging.warning(f"[-] Could not setup/verify ipset or iptables (is sudo missing?): {e}")

def block_ip(ip):
    """Add offending IP to ddos_blocklist."""
    try:
        # Run ipset add ddos_blocklist <ip>
        res = subprocess.run(
            ["ipset", "add", "ddos_blocklist", ip, "-exist"],
            capture_output=True,
            text=True
        )
        if res.returncode == 0:
            logging.warning(f"[!!!] MITIGATION TRIGGERED: Blocked offending IP {ip}")
        else:
            logging.error(f"[-] Failed to block IP {ip}: {res.stderr.strip()}")
    except Exception as e:
        logging.error(f"[-] Error calling ipset: {e}")

def decode_ip(ip_bytes):
    """Decode 16-byte IPv6 representation to standard IPv4 or IPv6 string."""
    try:
        ip_v6 = ipaddress.IPv6Address(ip_bytes)
        # If it's an IPv4-mapped IPv6 address (e.g. ::ffff:192.168.1.1), return the IPv4 part.
        if ip_v6.ipv4_mapped:
            return str(ip_v6.ipv4_mapped)
        return str(ip_v6)
    except Exception as e:
        logging.error(f"[-] Failed to parse IP bytes: {e}")
        return "Unknown"

def main():
    logging.info("╔══════════════════════════════════════════════════════════╗")
    logging.info("║  Mitigation Engine & IPC Receiver — Stage 2 (Python)     ║")
    logging.info("╚══════════════════════════════════════════════════════════╝")
    
    # 1. Load Trained Model
    if not os.path.exists(MODEL_PATH):
        logging.error(f"[-] Model not found at '{MODEL_PATH}'. Please run train.py first to train and save the model.")
        sys.exit(1)
        
    logging.info(f"[+] Loading Random Forest classifier from {MODEL_PATH}...")
    try:
        clf = joblib.load(MODEL_PATH)
        logging.info("[+] Classifier loaded successfully.")
    except Exception as e:
        logging.error(f"[-] Failed to load classifier: {e}")
        sys.exit(1)
        
    # 2. Setup Kernel ipset
    setup_ipset()
    
    # 3. Bind UNIX Socket
    if os.path.exists(SOCKET_PATH):
        try:
            os.remove(SOCKET_PATH)
        except OSError:
            pass
            
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(SOCKET_PATH)
        # Give permission to connect (in case of running across different privileges)
        os.chmod(SOCKET_PATH, 0o666)
        server.listen(5)
        logging.info(f"[+] Listening for Stage 1 on Unix socket: {SOCKET_PATH}")
    except Exception as e:
        logging.error(f"[-] Failed to bind socket to {SOCKET_PATH}: {e}")
        sys.exit(1)
        
    # 4. Main Event Loop
    try:
        while True:
            logging.info("[*] Waiting for Stage 1 connection...")
            conn, _ = server.accept()
            logging.info("[+] Connection accepted from Stage 1.")
            
            while True:
                try:
                    data = conn.recv(PAYLOAD_SIZE)
                    if not data:
                        logging.info("[-] Connection closed by Stage 1.")
                        break
                        
                    if len(data) < PAYLOAD_SIZE:
                        # Partial read, wait for rest
                        while len(data) < PAYLOAD_SIZE:
                            chunk = conn.recv(PAYLOAD_SIZE - len(data))
                            if not chunk:
                                break
                            data += chunk
                        if len(data) < PAYLOAD_SIZE:
                            logging.warning("[-] Received incomplete payload; ignoring.")
                            break
                            
                    # Unpack 88-byte payload
                    unpacked = struct.unpack(FEATURE_VECTOR_FORMAT, data)
                    
                    # Statistical features
                    entropy = unpacked[0]
                    ewma_rate = unpacked[1]
                    mean_h = unpacked[2]
                    mean_r = unpacked[3]
                    sigma_h = unpacked[4]
                    sigma_r = unpacked[5]
                    proto_ratio = unpacked[6]
                    dominant_ip_ratio = unpacked[7]
                    timestamp = unpacked[8]
                    
                    # IP Address
                    raw_ip = unpacked[9]
                    ip_str = decode_ip(raw_ip)
                    
                    # Assemble feature vector for classification
                    import pandas as pd
                    features_df = pd.DataFrame([[
                        entropy,
                        ewma_rate,
                        mean_h,
                        mean_r,
                        sigma_h,
                        sigma_r,
                        proto_ratio,
                        dominant_ip_ratio
                    ]], columns=[
                        "entropy",
                        "ewma_rate",
                        "mean_h",
                        "mean_r",
                        "sigma_h",
                        "sigma_r",
                        "proto_ratio",
                        "dominant_ip_ratio"
                    ])
                    
                    # Predict Traffic Class
                    pred_class = int(clf.predict(features_df)[0])
                    
                    class_labels = {
                        0: "Normal",
                        1: "Flash Crowd",
                        2: "DDoS"
                    }
                    pred_name = class_labels.get(pred_class, "Unknown")
                    
                    logging.info(
                        f"CLASSIFY | Prediction: {pred_name} ({pred_class}) | "
                        f"Rate: {ewma_rate:.1f} pps | Entropy: {entropy:.3f} | "
                        f"Dominant IP: {ip_str} ({dominant_ip_ratio*100:.1f}%)"
                    )
                    
                    # Perform Mitigation
                    if pred_class == 2:
                        if ip_str != "Unknown" and ip_str != "0.0.0.0" and ip_str != "::":
                            block_ip(ip_str)
                        else:
                            logging.warning("[-] DDoS detected but dominant IP is unknown or invalid; skipping block.")
                            
                except socket.error as se:
                    logging.warning(f"[-] Socket read error: {se}")
                    break
                except Exception as e:
                    logging.error(f"[-] Error processing feature vector: {e}")
                    break
                    
            conn.close()
            
    except KeyboardInterrupt:
        logging.info("\n[*] Shutdown requested by user.")
    finally:
        if os.path.exists(SOCKET_PATH):
            try:
                os.remove(SOCKET_PATH)
            except OSError:
                pass
        logging.info("[+] Socket cleaned up. Exiting.")

if __name__ == "__main__":
    main()
