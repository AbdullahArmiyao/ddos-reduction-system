#!/usr/bin/env python3
"""
stage2.py — Stage 2: Real-time IPC Classifier & Mitigation Engine + Web API Console
---------------------------------------------------------------------------------
Listens on the Unix Domain Socket at /tmp/ddos_stage1.sock for 88-byte feature
vectors containing window statistics and the dominant IP address.
Predicts traffic class (0: Normal, 1: Flash Crowd, 2: DDoS) in real-time
and triggers kernel-level mitigation via ipset for DDoS.

Features integrated:
- FastAPI backend serving multi-page HTML console under /static/
- User Authentication (salted SHA-256) with 10-minute session limits
- Persistence of incident logs and Welford histories in SQLite
- Active connection flow visualizer pulling from Stage 1 active flow logs
- Dynamic kernel blocklist viewer and administrative whitelist manager
- CSV/PDF Incident Report Exporter embedding base64-decoded Chart.js graphs
"""

import os
import sys
import time
import json
import socket
import struct
import ipaddress
import subprocess
import logging
import sqlite3
import hashlib
import secrets
import threading
from io import BytesIO
from typing import List, Optional
import joblib

# FastAPI Imports
from fastapi import FastAPI, Depends, HTTPException, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ReportLab PDF Imports
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Configuration Paths
SOCKET_PATH = "/tmp/ddos_stage1.sock"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(SCRIPT_DIR, "ddos_rf_model.joblib")
FEATURE_VECTOR_FORMAT = "<9d16s"  # 9 x f64 (72 bytes) + 16-byte IP address = 88 bytes
PAYLOAD_SIZE = struct.calcsize(FEATURE_VECTOR_FORMAT)

DB_PATH = os.environ.get("DB_PATH", os.path.join(SCRIPT_DIR, "stage2.db"))
WHITELIST_PATH = os.path.join(SCRIPT_DIR, "whitelist.json")
VICTIMS_PATH = os.path.join(SCRIPT_DIR, "victims.json")
FLOWS_PATH = "/tmp/ddos_active_flows.json"

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] stage2: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(SCRIPT_DIR, "stage2.log"), mode="a")
    ]
)

# -----------------------------------------------------------------------------
# Configuration Helper Functions
# -----------------------------------------------------------------------------

def load_json_file(path, default):
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(default, f)
        return default
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default

def save_json_file(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logging.error(f"[-] Failed to save configuration to {path}: {e}")

# Global state trackers in memory (synced to SQLite/JSON)
last_metrics = {
    "entropy": 0.0,
    "ewma_rate": 0.0,
    "mean_h": 0.0,
    "mean_r": 0.0,
    "sigma_h": 0.0,
    "sigma_r": 0.0,
    "proto_ratio": 1.0,
    "dominant_ip_ratio": 0.0,
    "timestamp": 0.0,
    "k_multiplier": 2.0,
    "cooldown": 0,
    "latest_classification": "Normal"
}

active_sessions = {}  # session_token -> last_active_timestamp

# -----------------------------------------------------------------------------
# Kernel netfilter blocklist control (ipset / iptables)
# -----------------------------------------------------------------------------

def setup_ipset():
    """Ensure the target ipset list exists and is linked to iptables rules."""
    try:
        # Create hash:ip set if it doesn't exist
        subprocess.run(
            ["ipset", "create", "ddos_blocklist", "hash:ip", "timeout", "3600"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        logging.info("[+] Kernel ipset 'ddos_blocklist' verified/created.")

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
        logging.warning(f"[-] Could not setup/verify ipset or iptables: {e}")

recently_blocked = {}

def block_ip(ip, duration=3600):
    """Add offending IP to ddos_blocklist."""
    global recently_blocked
    now = time.time()
    
    if ip in recently_blocked and now - recently_blocked[ip] < 10.0:
        return
        
    try:
        # Check whitelist bypass
        whitelist = load_json_file(WHITELIST_PATH, [])
        if ip in whitelist:
            logging.info(f"[Whitelist Bypass] Skipping block for whitelisted administrative IP: {ip}")
            return

        res = subprocess.run(
            ["ipset", "add", "ddos_blocklist", ip, "timeout", str(duration), "-exist"],
            capture_output=True,
            text=True
        )
        if res.returncode == 0:
            logging.warning(f"[!!!] MITIGATION TRIGGERED: Blocked offending IP {ip} (duration: {duration}s)")
            # Log to SQLite
            log_incident(now, ip, "DDoS")
        else:
            logging.error(f"[-] Failed to block IP {ip}: {res.stderr.strip()}")
    except Exception as e:
        logging.error(f"[-] Error calling ipset: {e}")
    finally:
        recently_blocked[ip] = now

def unblock_ip(ip):
    """Remove IP from ddos_blocklist."""
    try:
        res = subprocess.run(
            ["ipset", "del", "ddos_blocklist", ip],
            capture_output=True,
            text=True
        )
        if res.returncode == 0:
            logging.info(f"[+] Released firewall block for IP {ip}")
            return True
        else:
            logging.error(f"[-] Failed to release IP {ip}: {res.stderr.strip()}")
            return False
    except Exception as e:
        logging.error(f"[-] Error calling ipset: {e}")
        return False

def get_blocked_ips():
    """Extract blocked IPs and remaining timeouts directly from kernel."""
    try:
        res = subprocess.run(["ipset", "list", "ddos_blocklist"], capture_output=True, text=True)
        if res.returncode != 0:
            return []
        lines = res.stdout.split('\n')
        members_idx = -1
        for i, line in enumerate(lines):
            if line.startswith("Members:"):
                members_idx = i
                break
        if members_idx == -1:
            return []
        
        blocked = []
        for line in lines[members_idx+1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "timeout":
                blocked.append({"ip": parts[0], "remaining_seconds": int(parts[2])})
            else:
                blocked.append({"ip": parts[0], "remaining_seconds": 3600})
        return blocked
    except Exception:
        return []

def decode_ip(ip_bytes):
    try:
        ip_v6 = ipaddress.IPv6Address(ip_bytes)
        if ip_v6.ipv4_mapped:
            return str(ip_v6.ipv4_mapped)
        return str(ip_v6)
    except Exception as e:
        logging.error(f"[-] Failed to parse IP bytes: {e}")
        return "Unknown"

# -----------------------------------------------------------------------------
# SQLite Audit Database Helpers
# -----------------------------------------------------------------------------

def log_incident(timestamp, src_ip, classification):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO logs (timestamp, src_ip, dst_ip, proto, rate, entropy, classification) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (timestamp, src_ip, "10.0.0.3", "MIXED", last_metrics["ewma_rate"], last_metrics["entropy"], classification)
        )
        # Purge old logs to prevent size explosion (keep last 5000)
        cursor.execute("DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT 5000)")
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"[-] Failed to write incident to SQLite: {e}")

def log_metrics_history(timestamp, rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO metrics_history (timestamp, ewma_rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k_multiplier) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k)
        )
        # Purge old metrics history (keep last 1000)
        cursor.execute("DELETE FROM metrics_history WHERE id NOT IN (SELECT id FROM metrics_history ORDER BY id DESC LIMIT 1000)")
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"[-] Failed to save metrics history: {e}")

# -----------------------------------------------------------------------------
# IPC Socket Receiver Thread
# -----------------------------------------------------------------------------

def run_ipc_receiver():
    global last_metrics
    
    # Setup ipset
    setup_ipset()

    # Load Model
    if not os.path.exists(MODEL_PATH):
        logging.error(f"[-] Model not found at '{MODEL_PATH}'. UI will run in passive mode.")
        clf = None
    else:
        try:
            clf = joblib.load(MODEL_PATH)
            logging.info("[+] ML Classifier loaded successfully.")
        except Exception as e:
            logging.error(f"[-] Failed to load classifier: {e}")
            clf = None

    if os.path.exists(SOCKET_PATH):
        try:
            os.remove(SOCKET_PATH)
        except OSError:
            pass
            
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(SOCKET_PATH)
        os.chmod(SOCKET_PATH, 0o666)
        server.listen(5)
        logging.info(f"[+] IPC socket listening on: {SOCKET_PATH}")
    except Exception as e:
        logging.error(f"[-] Failed to bind socket to {SOCKET_PATH}: {e}")
        return

    while True:
        try:
            conn, _ = server.accept()
            while True:
                data = conn.recv(PAYLOAD_SIZE)
                if not data:
                    break
                if len(data) < PAYLOAD_SIZE:
                    while len(data) < PAYLOAD_SIZE:
                        chunk = conn.recv(PAYLOAD_SIZE - len(data))
                        if not chunk:
                            break
                        data += chunk
                    if len(data) < PAYLOAD_SIZE:
                        break
                        
                unpacked = struct.unpack(FEATURE_VECTOR_FORMAT, data)
                entropy = unpacked[0]
                ewma_rate = unpacked[1]
                mean_h = unpacked[2]
                mean_r = unpacked[3]
                sigma_h = unpacked[4]
                sigma_r = unpacked[5]
                proto_ratio = unpacked[6]
                dominant_ip_ratio = unpacked[7]
                timestamp = unpacked[8]
                ip_str = decode_ip(unpacked[9])

                # Calculate delta features
                delta_rate = ewma_rate - mean_r
                delta_entropy = entropy - mean_h

                pred_class = 0
                if clf:
                    import pandas as pd
                    features_df = pd.DataFrame([[
                        entropy, ewma_rate, mean_h, mean_r, sigma_h, sigma_r,
                        proto_ratio, dominant_ip_ratio, delta_rate, delta_entropy
                    ]], columns=[
                        "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
                        "proto_ratio", "dominant_ip_ratio", "delta_rate", "delta_entropy"
                    ])
                    pred_class = int(clf.predict(features_df)[0])

                # Safety overrides
                if pred_class in (0, 1) and ewma_rate > 2000.0:
                    if ewma_rate > 10000.0:
                        pred_class = 2
                    elif entropy < 3.5 or dominant_ip_ratio > 0.75:
                        pred_class = 2
                    else:
                        pred_class = 1

                class_names = {0: "Normal", 1: "Flash Crowd", 2: "DDoS"}
                pred_name = class_names.get(pred_class, "Normal")

                # Update live stats
                last_metrics = {
                    "entropy": entropy,
                    "ewma_rate": ewma_rate,
                    "mean_h": mean_h,
                    "mean_r": mean_r,
                    "sigma_h": sigma_h,
                    "sigma_r": sigma_r,
                    "proto_ratio": proto_ratio,
                    "dominant_ip_ratio": dominant_ip_ratio,
                    "timestamp": timestamp,
                    "k_multiplier": 2.0,
                    "cooldown": 0,
                    "latest_classification": pred_name
                }

                # Save history
                log_metrics_history(timestamp, ewma_rate, entropy, mean_h, mean_r, sigma_h, sigma_r, 2.0)

                # Trigger block
                if pred_class == 2:
                    if ip_str not in ("Unknown", "0.0.0.0", "::"):
                        block_ip(ip_str)
                elif pred_class == 1:
                    # Log flash crowd incident
                    log_incident(timestamp, ip_str, "Flash Crowd")

            conn.close()
        except Exception as e:
            logging.error(f"[-] Socket read loop error: {e}")
            time.sleep(1)

# -----------------------------------------------------------------------------
# FastAPI Core Web App
# -----------------------------------------------------------------------------

app = FastAPI(title="SHIELD Gateway Management Console", docs_url=None, redoc_url=None)

# Mount static files folder
app.mount("/static", StaticFiles(directory=os.path.join(SCRIPT_DIR, "static")), name="static")

# Middleware: Verify Cookie Authenticated Sessions
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    # Automatically normalize active-ips.html (hyphen) to active_ips.html (underscore)
    if "active-ips.html" in path:
        new_path = path.replace("active-ips.html", "active_ips.html")
        if not new_path.startswith("/static/"):
            new_path = f"/static{new_path}"
        return RedirectResponse(url=new_path)

    # Automatically redirect root-level HTML file requests to /static/ path
    if path != "/" and path.endswith(".html") and not path.startswith("/static/"):
        return RedirectResponse(url=f"/static{path}")

    # Skip auth checks for login pages, API endpoints, css assets
    if path.startswith("/static/login.html") or path.startswith("/api/login") or path.startswith("/static/base.css"):
        return await call_next(request)

    # Protected paths: static HTMLs, API routes, root path
    if path.endswith(".html") or path == "/" or path.startswith("/api/"):
        session_id = request.cookies.get("session_id")
        is_valid = False
        if session_id in active_sessions:
            # Check 10 minutes timeout (600s)
            if time.time() - active_sessions[session_id] <= 600:
                active_sessions[session_id] = time.time()  # refresh
                is_valid = True
            else:
                del active_sessions[session_id]

        if not is_valid:
            if path.startswith("/api/"):
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=401, content={"detail": "Session expired. Re-authenticate."})
            return RedirectResponse(url="/static/login.html")

    return await call_next(request)

@app.get("/")
def read_root():
    return RedirectResponse(url="/static/index.html")

# -----------------------------------------------------------------------------
# API Handlers
# -----------------------------------------------------------------------------

@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...)):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin credentials.")
            
        stored_hash, salt = row
        hasher = hashlib.sha256()
        hasher.update((password + salt).encode('utf-8'))
        
        if hasher.hexdigest() == stored_hash:
            # Generate session
            session_token = secrets.token_hex(24)
            active_sessions[session_token] = time.time()
            response = RedirectResponse(url="/static/index.html", status_code=status.HTTP_303_SEE_OTHER)
            response.set_cookie(
                key="session_id",
                value=session_token,
                max_age=600,
                httponly=True,
                samesite="lax"
            )
            return response
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Handshake credentials rejected.")
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/logout")
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id in active_sessions:
        del active_sessions[session_id]
    response = RedirectResponse(url="/static/login.html")
    response.delete_cookie("session_id")
    return response

def get_interface_ip(ifname):
    import socket
    import fcntl
    import struct
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        return "UNASSIGNED"

def is_interface_promisc(ifname):
    try:
        with open(f"/sys/class/net/{ifname}/flags", "r") as f:
            flags = int(f.read().strip(), 16)
            return (flags & 0x100) != 0
    except Exception:
        return False

@app.get("/api/state")
def get_state():
    # Load flows
    active_flows = []
    if os.path.exists(FLOWS_PATH):
        try:
            with open(FLOWS_PATH, "r") as f:
                active_flows = json.load(f).get("active_ips", [])
        except Exception:
            pass

    # Load Whitelisted
    whitelist = load_json_file(WHITELIST_PATH, [])
    # Load Victims
    victims = load_json_file(VICTIMS_PATH, [])
    
    # Load Blocks
    blocked_detail = get_blocked_ips()
    blocked_ips_only = [b["ip"] for b in blocked_detail]

    # Load Interfaces
    interfaces = []
    try:
        for name in os.listdir('/sys/class/net'):
            try:
                with open(f"/sys/class/net/{name}/operstate", "r") as f:
                    up = f.read().strip() == "up"
            except Exception:
                up = False
            try:
                with open(f"/sys/class/net/{name}/address", "r") as f:
                    mac = f.read().strip()
            except Exception:
                mac = ""
            ip = get_interface_ip(name)
            promisc = is_interface_promisc(name)
            interfaces.append({"name": name, "mac": mac, "ip": ip, "up": up, "promisc": promisc})
    except Exception:
        pass

    # Read latest logs from db
    latest_logs = []
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, src_ip, classification FROM logs ORDER BY id DESC LIMIT 5")
        latest_logs = [{"timestamp": r[0], "src_ip": r[1], "classification": r[2]} for r in cursor.fetchall()]
        conn.close()
    except Exception:
        pass

    # Read active sniffer interface from stage 1 service (simulate or read default ens19)
    active_interface = "ens19"
    try:
        if os.path.exists("/etc/systemd/system/ddos-stage1.service"):
            with open("/etc/systemd/system/ddos-stage1.service", "r") as f:
                content = f.read()
                for part in content.split():
                    if part.startswith("--interface"):
                        idx = content.split().index(part)
                        active_interface = content.split()[idx+1]
                        break
    except Exception:
        pass

    return {
        **last_metrics,
        "active_flows": active_flows,
        "whitelisted_ips": whitelist,
        "blocked_ips": blocked_ips_only,
        "blocked_ips_detail": blocked_detail,
        "blocked_count": len(blocked_ips_only),
        "victim_targets": victims,
        "interfaces": interfaces,
        "active_interface": active_interface,
        "latest_logs": latest_logs
    }

@app.get("/api/history")
def get_history():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT timestamp, ewma_rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k_multiplier "
            "FROM metrics_history ORDER BY id DESC LIMIT 30"
        )
        rows = cursor.fetchall()
        conn.close()
        
        # Reverse to get chronological order
        rows.reverse()
        return [
            {
                "timestamp": r[0],
                "ewma_rate": r[1],
                "entropy": r[2],
                "mean_h": r[3],
                "mean_r": r[4],
                "sigma_h": r[5],
                "sigma_r": r[6],
                "k_multiplier": r[7]
            }
            for r in rows
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Whitelist endpoints
class IpPayload(BaseModel):
    ip: str

@app.post("/api/whitelist")
def add_whitelist(payload: IpPayload):
    whitelist = load_json_file(WHITELIST_PATH, [])
    if payload.ip not in whitelist:
        whitelist.append(payload.ip)
        save_json_file(WHITELIST_PATH, whitelist)
    return {"status": "success"}

@app.delete("/api/whitelist")
def delete_whitelist(ip: str):
    whitelist = load_json_file(WHITELIST_PATH, [])
    if ip in whitelist:
        whitelist.remove(ip)
        save_json_file(WHITELIST_PATH, whitelist)
    return {"status": "success"}

# Victim targets endpoints
class VictimPayload(BaseModel):
    ip: str
    description: str

@app.post("/api/victim")
def add_victim(payload: VictimPayload):
    victims = load_json_file(VICTIMS_PATH, [])
    for v in victims:
        if v["ip"] == payload.ip:
            raise HTTPException(status_code=400, detail="Asset IP is already deployed.")
    victims.append({"ip": payload.ip, "description": payload.description, "active": True})
    save_json_file(VICTIMS_PATH, victims)
    return {"status": "success"}

@app.delete("/api/victim")
def delete_victim(ip: str):
    victims = load_json_file(VICTIMS_PATH, [])
    victims = [v for v in victims if v["ip"] != ip]
    save_json_file(VICTIMS_PATH, victims)
    return {"status": "success"}

@app.post("/api/victim/toggle")
def toggle_victim(ip: str):
    victims = load_json_file(VICTIMS_PATH, [])
    for v in victims:
        if v["ip"] == ip:
            v["active"] = not v["active"]
    save_json_file(VICTIMS_PATH, victims)
    return {"status": "success"}

# Firewall blocks endpoints
@app.post("/api/firewall/block")
def manual_block(payload: IpPayload):
    block_ip(payload.ip, duration=600)
    return {"status": "success"}

@app.post("/api/firewall/unblock")
def manual_unblock(payload: IpPayload):
    if unblock_ip(payload.ip):
        return {"status": "success"}
    raise HTTPException(status_code=500, detail="Failed to release firewall block.")

# Logs API
@app.get("/api/logs")
def get_logs(classification: str = "ALL"):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        if classification == "ALL":
            cursor.execute("SELECT timestamp, src_ip, dst_ip, proto, rate, entropy, classification FROM logs ORDER BY id DESC LIMIT 100")
        else:
            cursor.execute(
                "SELECT timestamp, src_ip, dst_ip, proto, rate, entropy, classification FROM logs WHERE classification = ? ORDER BY id DESC LIMIT 100",
                (classification,)
            )
        rows = cursor.fetchall()
        conn.close()
        return [
            {
                "timestamp": r[0],
                "src_ip": r[1],
                "dst_ip": r[2],
                "proto": r[3],
                "rate": r[4],
                "entropy": r[5],
                "classification": r[6]
            }
            for r in rows
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs/export/csv")
def export_csv():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, src_ip, dst_ip, proto, rate, entropy, classification FROM logs ORDER BY id DESC")
        rows = cursor.fetchall()
        conn.close()

        def iter_csv():
            yield "Timestamp,Source IP,Destination IP,Protocol,Packet Rate (PPS),Shannon Entropy (bits),Classification\n"
            for r in rows:
                date_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r[0]))
                yield f"{date_str},{r[1]},{r[2] or ''},{r[3] or ''},{r[4]:.2f},{r[5]:.4f},{r[6]}\n"

        return StreamingResponse(
            iter_csv(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=shield_gateway_logs.csv"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# PDF Generator Endpoint
class PdfReportPayload(BaseModel):
    rate_chart_base64: str
    entropy_chart_base64: str

@app.post("/api/logs/export/pdf")
def export_pdf(payload: PdfReportPayload):
    import base64
    
    # Decode charts
    try:
        rate_data = base64.b64decode(payload.rate_chart_base64.split(",")[1])
        entropy_data = base64.b64decode(payload.entropy_chart_base64.split(",")[1])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 chart data: {e}")

    # Write temporary image files
    temp_rate_path = os.path.join(SCRIPT_DIR, "temp_rate.png")
    temp_entropy_path = os.path.join(SCRIPT_DIR, "temp_entropy.png")
    try:
        with open(temp_rate_path, "wb") as f:
            f.write(rate_data)
        with open(temp_entropy_path, "wb") as f:
            f.write(entropy_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to decode chart images: {e}")

    pdf_buffer = BytesIO()
    try:
        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=20,
            textColor=colors.HexColor('#00a2b0'),
            spaceAfter=15
        )
        subtitle_style = ParagraphStyle(
            'SubTitleStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#5c7b80'),
            spaceAfter=25
        )
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#333333'),
            spaceAfter=10
        )
        header_style = ParagraphStyle(
            'HeaderStyle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=11,
            textColor=colors.HexColor('#00a2b0'),
            spaceAfter=8
        )

        elements = []
        
        # Title
        elements.append(Paragraph("SHIELD GATEWAY INCIDENT REPORT", title_style))
        elements.append(Paragraph(f"GENERATED: {time.strftime('%Y-%m-%d %H:%M:%S')} // SECURE LOG AUDITING", subtitle_style))
        
        # System Overview Info
        blocked_ips = get_blocked_ips()
        overview_data = [
            ["OPERATIONAL MODE", "TRANSPARENT BRIDGE"],
            ["ML CLASSIFIER MODEL", "RANDOM FOREST MULTI-CLASS"],
            ["ACTIVE BLOCKED HOSTS", f"{len(blocked_ips)} IPS IN KERNEL SET"],
            ["CURRENT INTERFACE", "ens19"]
        ]
        t_overview = Table(overview_data, colWidths=[200, 300])
        t_overview.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f5fcfd')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#00a2b0')),
            ('PADDING', (0,0), (-1,-1), 8),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#111111')),
        ]))
        elements.append(t_overview)
        elements.append(Spacer(1, 20))

        # Embed Chart Images
        elements.append(Paragraph("HISTORICAL ANOMALY GRAPHICS", header_style))
        chart_table_data = [
            [RLImage(temp_rate_path, width=250, height=150), RLImage(temp_entropy_path, width=250, height=150)]
        ]
        t_charts = Table(chart_table_data, colWidths=[270, 270])
        t_charts.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(t_charts)
        elements.append(Spacer(1, 20))

        # Recent Logs Table
        elements.append(Paragraph("LATEST RECORDED THREAT METADATA (LAST 5 INCIDENTS)", header_style))
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, src_ip, rate, entropy, classification FROM logs ORDER BY id DESC LIMIT 5")
        rows = cursor.fetchall()
        conn.close()

        log_table_data = [["TIMESTAMP", "SOURCE IP", "RATE", "ENTROPY", "CLASSIFICATION"]]
        for r in rows:
            date_str = time.strftime('%H:%M:%S', time.localtime(r[0]))
            log_table_data.append([
                date_str,
                r[1],
                f"{r[2]:.1f} pps",
                f"{r[3]:.4f}",
                r[4].upper()
            ])
            
        t_logs = Table(log_table_data, colWidths=[100, 120, 100, 100, 120])
        t_logs.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#00a2b0')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f9f9f9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('ALIGN', (0,0), (-1,-1), 'CENTER')
        ]))
        elements.append(t_logs)

        # Build PDF
        doc.build(elements)
        pdf_buffer.seek(0)
        
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=shield_gateway_report.pdf"}
        )
    except Exception as e:
        logging.error(f"[-] Failed to generate PDF Document: {e}")
        raise HTTPException(status_code=500, detail=f"PDF build error: {e}")
    finally:
        # Clean up temp image files
        if os.path.exists(temp_rate_path):
            os.remove(temp_rate_path)
        if os.path.exists(temp_entropy_path):
            os.remove(temp_entropy_path)

# -----------------------------------------------------------------------------
# Main Application Launch Hook
# -----------------------------------------------------------------------------

def start_api_server():
    import uvicorn
    logging.info("[+] Starting Uvicorn API Server on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")

def main():
    # Ensure SQLite initialized
    if not os.path.exists(DB_PATH):
        logging.info("[+] DB missing; initializing database tables...")
        # Create directories and run quick init
        os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT, salt TEXT)")
        cursor.execute("CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, src_ip TEXT, dst_ip TEXT, proto TEXT, rate REAL, entropy REAL, classification TEXT)")
        cursor.execute("CREATE TABLE IF NOT EXISTS metrics_history (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, ewma_rate REAL, entropy REAL, mean_h REAL, mean_r REAL, sigma_h REAL, sigma_r REAL, k_multiplier REAL)")
        # Insert default password just in case (setup_admin.py handles this properly)
        cursor.execute("INSERT OR IGNORE INTO users VALUES ('admin', '4a0f4439c2794eb8f73111f1816e8e8156641d40a23277717469a4731c3c97e6', 'abcdef0123456789')")
        conn.commit()
        conn.close()

    # Ensure configs initialized
    load_json_file(WHITELIST_PATH, [])
    load_json_file(VICTIMS_PATH, [])

    # Start IPC socket listener thread
    ipc_thread = threading.Thread(target=run_ipc_receiver, daemon=True)
    ipc_thread.start()

    # Start FastAPI / Uvicorn server synchronously on main thread
    start_api_server()

if __name__ == "__main__":
    main()
