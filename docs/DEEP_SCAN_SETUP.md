# PhishGuard AI V6.3 — Deep Scan VM Setup Guide

## Overview

PhishGuard V6.3 replaces the Docker-based Deep Scan environment with a **VirtualBox-based isolated analysis VM**. The VM runs a lightweight Linux guest containing:

- Python 3.10+
- Playwright + Chromium (headless, fully isolated)
- The `analysis_agent/` Flask HTTP server

The **Windows host Flask backend** never opens target URLs itself. All browser execution happens **inside the VM only**.

> **Security Note:** The VM is described as an *isolated disposable browser analysis environment*. It provides meaningful isolation from the Windows host, but it is not a claim of perfect containment. Do not treat it as a substitute for a full enterprise sandbox appliance.

---

## Architecture

```
Windows Host (Flask Backend)
        │  HTTP POST /analyze
        │  (Host-Only vboxnet — NOT internet-accessible)
        ▼
VirtualBox Linux Analysis VM  (192.168.56.101:8765)
        │  Playwright Chromium (headless, fresh context per scan)
        ▼
Target Website (internet via NAT adapter)
```

**Key properties:**
- The VM agent NEVER accesses the Windows host filesystem
- The browser context is fresh per scan (no cookies, no extensions, no profiles)
- Camera, microphone, clipboard, geolocation: denied inside the browser
- Downloads are disabled in the browser
- Every redirect destination is validated against the in-VM SSRF guard

---

## Step 1 — Install VirtualBox

Download and install [VirtualBox for Windows](https://www.virtualbox.org/wiki/Downloads).

Recommended version: **7.0+**

---

## Step 2 — Create the Linux VM

1. **New VM** → Name: `PhishGuard-Analysis-VM`
2. **OS**: Linux 64-bit (Debian 12 or Ubuntu 22.04 LTS recommended)
3. **RAM**: 2048 MB minimum (4096 MB recommended for Chromium)
4. **CPU**: 2 cores
5. **Storage**: 20 GB dynamically allocated VDI

### Network Adapters

| Adapter | Type | Purpose |
|---------|------|---------|
| Adapter 1 | **Host-Only** (`vboxnet0`) | Flask ↔ VM communication |
| Adapter 2 | **NAT** | VM → internet (for browser to reach target sites) |

> ⚠️ **Do NOT use Bridged networking** as it would expose the VM to your LAN.

### Create the Host-Only network (if not already present):
`File → Host Network Manager → Create → 192.168.56.1/24`

---

## Step 3 — Configure the VM network inside Linux

After installing the OS, configure the host-only adapter statically:

```bash
# Set the host-only NIC (usually eth1 or enp0s8) to 192.168.56.101
ip addr add 192.168.56.101/24 dev eth1
ip link set eth1 up
```

Or create `/etc/network/interfaces.d/phishguard`:
```
auto eth1
iface eth1 inet static
    address 192.168.56.101
    netmask 255.255.255.0
```

Verify connectivity from Windows:
```powershell
ping 192.168.56.101
```

---

## Step 4 — Install Python + Playwright inside the VM

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv tesseract-ocr tesseract-ocr-eng

# Create or use the virtual environment
python3 -m venv /home/vikas/phishguard-venv
source /home/vikas/phishguard-venv/bin/activate

pip install flask flask-cors playwright pillow pytesseract

playwright install chromium
playwright install-deps chromium
```

---

## Step 5 — Deploy the analysis agent

Use the VirtualBox Shared Folder (`PhishGuard` mounted at `/media/sf_PhishGuard`) or copy `analysis_agent/` to `/opt/phishguard-agent/`.

---

## Step 6 — Start the analysis agent (systemd Service)

Configure the systemd service at `/etc/systemd/system/phishguard-agent.service`:

```ini
[Unit]
Description=PhishGuard AI Analysis VM Agent
After=network.target

[Service]
Type=simple
User=vikas
WorkingDirectory=/media/sf_PhishGuard
ExecStart=/home/vikas/phishguard-venv/bin/python /media/sf_PhishGuard/app.py
Restart=always
RestartSec=3
Environment=AGENT_PORT=8765
Environment=AGENT_BIND_HOST=0.0.0.0

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable phishguard-agent
sudo systemctl restart phishguard-agent
```

Verify service status:
```bash
sudo systemctl status phishguard-agent
```

Expected output:
```
Active: active (running)
[VM Agent] Starting PhishGuard Analysis Agent v1.0.0
[VM Agent] Listening on 0.0.0.0:8765
[VM Agent] Isolated disposable browser analysis environment
```

---

## Step 7 — Verify from Windows

```powershell
# Direct VM agent health check (verifies Playwright and Tesseract OCR)
curl http://192.168.56.101:8765/health

# Flask backend probe (verifies full integration status)
curl http://localhost:5000/health
```

---

## Environment Variables (host Flask side)

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHGUARD_VM_IP` | `192.168.56.101` | VM analysis agent IP |
| `PHISHGUARD_VM_PORT` | `8765` | VM analysis agent port |
| `PHISHGUARD_VM_TIMEOUT` | `30` | Max seconds for a scan response |
| `PHISHGUARD_VM_BROWSER_MS` | `12000` | Browser page-load timeout (ms) |
| `PHISHGUARD_VM_MAX_REDIRECTS` | `5` | Max redirects per scan |
| `PHISHGUARD_VM_MAX_RESPONSE_KB` | `2048` | Max HTML response size (KB) |

---

## Starting and Stopping the VM

```powershell
# Start headless
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm "PhishGuard-Analysis-VM" --type headless

# Check state
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" showvminfo "PhishGuard-Analysis-VM" --machinereadable | Select-String "VMState"

# Stop (graceful)
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "PhishGuard-Analysis-VM" acpipowerbutton

# Stop (hard)
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "PhishGuard-Analysis-VM" poweroff
```

---

## Rollback to Docker controller

The original Docker controller is preserved at `backend/deep_scan/sandbox_controller.py`.

To roll back, change one line in `backend/app.py` (line ~40):

```python
# From:
from deep_scan.vm_controller import check_sandbox_availability, run_deep_scan, get_sandbox_status

# To:
from deep_scan.sandbox_controller import check_sandbox_availability, run_deep_scan, get_sandbox_status
```

---

## Running the test suite

```powershell
cd backend

# Unit tests only (no Flask or VM required) — always run first
python -m pytest tests/test_phishguard.py -v -m unit

# Quick Scan integration tests (Flask required, no VM)
python -m pytest tests/test_phishguard.py -v -m quick

# Full suite including Deep Scan (both Flask and VM required)
python -m pytest tests/test_phishguard.py -v
```

---

## Quick Scan when VM is offline

The Quick Scan pipeline (CNN-BiLSTM + RoBERTa + Heuristics + Threat Repository) **is completely unaffected** by VM availability.

If Deep Scan is requested but the VM is unavailable:
- Response includes `"deep_scan": {"available": false}`
- The Quick Scan result and all AI verdicts are still returned
- Frontend banner shows "DEEP SCAN UNAVAILABLE" with the reason
- **The Windows host browser is NEVER opened for the target URL under any circumstances**
