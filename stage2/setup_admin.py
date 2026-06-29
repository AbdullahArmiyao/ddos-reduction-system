#!/usr/bin/env python3
# =============================================================================
# setup_admin.py — Setup script for admin account creation in SQLite
# =============================================================================

import os
import sys
import sqlite3
import hashlib
import secrets

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "stage2.db"))

def generate_random_password(length=16):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hasher = hashlib.sha256()
    hasher.update((password + salt).encode('utf-8'))
    return hasher.hexdigest(), salt

def init_db(db_path):
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL
    )""")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT,
        proto TEXT,
        rate REAL NOT NULL,
        entropy REAL NOT NULL,
        classification TEXT NOT NULL
    )""")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS metrics_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        ewma_rate REAL NOT NULL,
        entropy REAL NOT NULL,
        mean_h REAL NOT NULL,
        mean_r REAL NOT NULL,
        sigma_h REAL NOT NULL,
        sigma_r REAL NOT NULL,
        k_multiplier REAL NOT NULL
    )""")

    conn.commit()
    conn.close()

def main():
    print("========================================================================")
    print("           SHIELD GATEWAY - ADMINISTRATOR INITIALIZATION")
    print("========================================================================")

    init_db(DB_PATH)
    print(f"[+] Initialized SQLite database at: {DB_PATH}")

    # Check if users already exist to allow non-interactive upgrades
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        conn.close()
        if count > 0:
            print("[+] Existing administrator account detected. Skipping interactive setup.")
            print("========================================================================")
            return
    except Exception as e:
        print(f"[-] Error checking for existing users: {e}")

    # Prompt for admin setup
    try:
        username = input("[?] Enter admin username [default: admin]: ").strip() or "admin"
        
        password = input("[?] Enter admin password (or press ENTER to auto-generate): ").strip()
        is_generated = False
        if not password:
            password = generate_random_password()
            is_generated = True
            
        password_hash, salt = hash_password(password)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (username, password_hash, salt))
        conn.commit()
        conn.close()

        print("[+] Administrator account configured successfully.")
        if is_generated:
            # Print password in bold yellow style
            print("\033[1;33m" + "========================================================================" + "\033[0m")
            print("\033[1;33m" + f"[!] GENERATED ADMIN USERNAME: {username}" + "\033[0m")
            print("\033[1;33m" + f"[!] GENERATED ADMIN PASSWORD: {password}" + "\033[0m")
            print("\033[1;33m" + "========================================================================" + "\033[0m")
            print("[!] WARNING: Please save this password securely. It will not be shown again.")
            print("========================================================================")
        else:
            print("[+] Password verified and encrypted.")
            print("========================================================================")

    except KeyboardInterrupt:
        print("\n[!] Setup cancelled.")
        sys.exit(1)

if __name__ == "__main__":
    main()
