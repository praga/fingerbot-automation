# Tuya Fingerbot BLE Automation Service

A containerized Python automation engine and modern Web Dashboard to control a Tuya Fingerbot via Bluetooth Low Energy (BLE 4.x), automating mechanical button presses with robust scheduling, dual-countdown timers, and customizable intervals.

Deployable anywhere with Docker Compose (Linux, TrueNAS SCALE, Raspberry Pi, homelab servers) on port `8187` (or any custom port).

---

## 1. System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Docker Host / Server                        │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │     Docker Container: fingerbot-automation          │   │
│   │     (python:3.11-slim, Port 8187 -> 8085)          │   │
│   │                                                     │   │
│   │   [FastAPI + APScheduler] <──> [Web Dashboard]      │   │
│   │             │                                       │   │
│   │      [TuyaBleCodec] (Protocol v4.7 AES-128-CBC)     │   │
│   │             │                                       │   │
│   │      [Google Bumble Userspace HCI Stack]            │   │
│   └─────────────┬───────────────────────────────────────┘   │
│                 │ (Direct raw USB access: /dev/bus/usb)     │
│   ┌─────────────▼───────────────────────────────────────┐   │
│   │ CSR8510 A10 USB Dongle (0a12:0001, usb:0)           │   │
│   └─────────────┬───────────────────────────────────────┘   │
└─────────────────┼───────────────────────────────────────────┘
                  │ BLE 4.2 Advertisements & GATT
┌─────────────────▼───────────────────────────────────────────┐
│ Tuya BLE Fingerbot (Target MAC, GATT Handle 17 / 21)        │
│ Firmware: Protocol v4.7                                     │
└─────────────────────────────────────────────────────────────┘
```

### Why Google Bumble Userspace HCI?
TrueNAS SCALE Debian Bookworm kernel has `# CONFIG_BT is not set` by default, meaning the kernel has **zero BlueZ or Bluetooth subsystem support** (`hci0` does not exist).
By using **Google Bumble** in raw USB mode (`open_transport("usb:0")`), the application communicates directly with the CSR8510 USB controller endpoints in userspace, completely bypassing host kernel limitations.

---

## 2. Tuya BLE Protocol v4.7 Reverse Engineering & Auth

The Tuya Fingerbot runs **Tuya BLE Protocol v4.7**, which enforces strict packet framing, cryptographic key derivation, and opcode routing.

### 2.1 Packet Framing & Encoding
- **Variable-Length 7-Bit Integer Encoding**: Sequence numbers and packet lengths are packed/unpacked using protobuf-style varints (7 bits per byte, MSB set if continuation).
- **Protocol Version Header**: Packet fragment 0 must carry protocol byte `0x40` (`proto = 4`). Older `proto = 2` (`0x20`) packets cause immediate HCI disconnect (Reason `22`).
- **Encryption**: AES-128-CBC with a fresh 16-byte random IV prepended to every frame.
- **Checksum**: CRC16-Modbus (polynomial `0xA001`, initial `0xFFFF`) calculated over decrypted header + data.

### 2.2 Dual-Tier Cryptographic Key Hierarchy

| Key | Derivation | Purpose | Security Flag |
| :--- | :--- | :--- | :---: |
| **Login Key** | `MD5(LOCAL_KEY[:6])` | Used exclusively for the initial `DEV_INFO` request | `flag = 4` |
| **Session Key** | `MD5(LOCAL_KEY[:6] + srand)` | Dynamically generated from device `srand`; authorizes all DP commands | `flag = 5` |

> **Note**: `LOCAL_KEY[:6]` represents the first 6 ASCII characters of your 16-character Tuya Local Key.

### 2.3 Handshake & Authentication Flow
1. **Connect**: Connect to GATT server at configured `<TARGET_DEVICE_MAC>` (e.g. `AA:BB:CC:DD:EE:FF`).
2. **Subscribe**: Subscribe to notifications on **Handle 17** (`00000002-0000-1001-8001-00805f9b07d0`).
3. **Step 1: DEV_INFO (`cmd = 0x0000`, `flag = 4`)**:
   - Sent encrypted with `login_key`.
   - Fingerbot responds with `bound = True` and a 6-byte random nonce (`srand`, e.g., `ba77e829fffd`).
   - Driver derives dynamic `session_key = MD5(LOCAL_KEY[:6] + srand)`.
4. **Step 2: PAIR_REQ (`cmd = 0x0001`, `flag = 5`)**:
   - 44-byte padded payload: `UUID (16B) + LOCAL_KEY[:6] (6B) + DEV_ID (22B zero-padded)`.
   - Encrypted with `session_key`.
   - Device replies with `result = 2` (already paired confirmation). Session is now fully authorized for motor commands.

---

## 3. Firmware Data Point (DP) Schema & Motor Control

Earlier Tuya implementations targeted `cmd = 0x0002` and DP 101. On this firmware, legacy commands are ignored. The firmware utilizes **`cmd = 0x0027` (`FRM_DP_DATA_WRITE_REQ`)** with 2-byte KLV lengths.

Incoming hardware status reports (`cmd = 0x8006`) expose the actual internal schema:

```
Header: 00f00000008000 [DP_ID: 1B] [TYPE: 1B] [LEN: 2B] [VALUE: NB]
```

### Verified DP Mapping

| DP ID | Type | Length | Function | Values / Behavior |
| :---: | :---: | :---: | :--- | :--- |
| **1** | `0x01` (BOOL) | 1 byte | **Physical Motor Actuator Switch** | `1` = Extend / Push arm<br>`0` = Retract arm |
| **2** | `0x04` (ENUM) | 1 byte | **Operating Mode Setting** | `0` = Click Mode<br>`1` = Switch Mode |
| **3** | `0x02` (INT) | 4 bytes | **Click Sustain Duration** | Value in seconds (e.g. `0` = default momentary) |
| **5** | `0x02` (INT) | 4 bytes | **Arm Stroke Travel %** | `0` to `100` percent travel (factory default: `67%` / `0x43`) |
| **6** | `0x02` (INT) | 4 bytes | **Auxiliary Sensor / Config** | Internal state |
| **8** | `0x02` (INT) | 4 bytes | **Battery Level** | Current battery percentage (`0..100%`) |

### Motor Command Packet Structure (`cmd = 0x0027`)
```python
# KLV format for DP 1 True (Extend):
payload = bytes([0x00]) + struct.pack(">IBBHB", sn, 1, 1, 1, 1)
# Header: 0x00, SN: 4-byte uint, DP: 1, Type: 1 (BOOL), Len: 1, Value: 1

# KLV format for DP 1 False (Retract):
payload = bytes([0x00]) + struct.pack(">IBBHB", sn, 1, 1, 1, 0)
```

---

## 4. Automation Features & Timing

### 4.1 11-Minute Default Interval
The default recurring interval is set to **11.0 minutes** (`interval_minutes: 11.0`). This provides a safe grace period to prevent issues with 10-minute external timeout constraints.

### 4.2 In-Session Double-Press Actuation
At each automation interval (or when triggered manually), the Fingerbot executes a **double press** in a single BLE session:
1. Connect and perform session handshake.
2. **Press 1**: Extend arm (`DP 1 = 1`) $\rightarrow$ Hold for configured duration (default `2.0s`) $\rightarrow$ Retract arm (`DP 1 = 0`).
3. **Pause**: Hold retracted state for **5.0 seconds** (`repeat_delay_seconds = 5.0`).
4. **Press 2**: Extend arm (`DP 1 = 1`) $\rightarrow$ Hold for configured duration $\rightarrow$ Retract arm (`DP 1 = 0`).
5. Disconnect cleanly.

Both presses execute within ~12 seconds inside one BLE connection, minimizing battery consumption and Bluetooth radio contention.

---

## 5. Secrets Storage & Security

### 5.1 Where Secrets Are Stored

| Environment | Path | Description |
| :--- | :--- | :--- |
| **Host System** | `./data/config.json` (or configured host bind mount) | Persistent host storage |
| **Inside Docker Container** | `/app/data/config.json` | Application working configuration |
| **Git Repository** | `data/*.json` in [`.gitignore`](.gitignore) | **Excluded from Git** to prevent credential leaks |

### 5.2 Secret Contents in `config.json`
- `local_key`: 16-character cryptographic key required for AES handshake.
- `device_id`: 20-character virtual device ID from SmartLife / Tuya IoT Platform.
- `uuid`: 16-character device UUID.
- `device_mac`: Bluetooth MAC address (e.g. `AA:BB:CC:DD:EE:FF`).

A non-sensitive template is provided at [`data/config.example.json`](data/config.example.json).

---

## 6. How to Back Up Your Configuration & Secrets

### Method 1: Instant REST API Backup (From any machine on local network)
Run this command from your terminal to save a full backup:
```bash
curl -s http://<SERVER_IP>:8187/api/config > fingerbot_config_backup.json
```

### Method 2: Direct Host File Backup
From your host console:
```bash
cp ./data/config.json ./data/config.json.bak
```

### Restoring from Backup
If the container or host data is ever rebuilt, simply restore your saved JSON:
```bash
curl -X POST http://<SERVER_IP>:8187/api/config \
  -H "Content-Type: application/json" \
  -d @fingerbot_config_backup.json
```
Or copy it directly back to your persistent `./data/config.json` and restart the container.

---

## 7. REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/status` | Real-time scheduler state, countdown seconds, BLE status, and metrics |
| `POST` | `/api/automation/start` | Start recurring interval presses (`{"interval_minutes": 11.0, "stop_after_hours": 4.0}`) |
| `POST` | `/api/automation/update` | Update interval or duration limit on the fly without stopping |
| `POST` | `/api/automation/stop` | Stop active automation |
| `POST` | `/api/trigger` | Trigger immediate double-press actuation test |
| `GET` | `/api/config` | Retrieve current configuration and secrets |
| `POST` | `/api/config` | Update configuration settings |
| `GET` | `/api/logs` | Fetch real-time activity and actuation logs |
| `POST` | `/api/logs/clear` | Clear execution history |

---

## 8. Web Dashboard Access

The responsive web interface is accessible at:
```
http://<SERVER_IP>:8187  (or http://localhost:8187)
```

> **Port Mapping Note**: In [`docker-compose.yml`](docker-compose.yml), the service maps host port `8187` to internal container port `8085` (`ports: ["8187:8085"]`). To change the host port, simply modify the left-hand port value (e.g., `"8085:8085"` or `"9000:8085"`).

- **"Press Fingerbot"**: Triggers an on-demand double-press cycle immediately.
- **"Start Automation"**: Begins recurring 11-minute double presses with live dual countdowns (next press & auto-stop).
- **Settings Icon**: Edit MAC, Local Key, hold duration, double-press repeats, and daily active hours.

---

## 9. Diagnostic & Protocol Probing Tools (`tools/`)

The repository includes a suite of standalone command-line scripts in [`tools/`](tools/) useful for protocol analysis, hardware diagnostics, and testing without running the full web server:

| Script | Purpose |
| :--- | :--- |
| [`tools/actuate_live.py`](tools/actuate_live.py) | Standalone CLI script to run the authenticated v4 handshake and actuate the Fingerbot motor. |
| [`tools/test_v4_firmware_handshake.py`](tools/test_v4_firmware_handshake.py) | Comprehensive handshake validation script verifying `DEV_INFO`, `srand` extraction, session key derivation, and `PAIR_REQ` negotiation. |
| [`tools/diagnose_motor.py`](tools/diagnose_motor.py) | Motor travel, stroke duration, and mechanical timing diagnostic tool. |
| [`tools/probe_key4.py`](tools/probe_key4.py) | Key derivation and security flag validation probe. |
| [`tools/test_bt785_fingerbot.py`](tools/test_bt785_fingerbot.py) | Low-level GATT characteristic probe and raw packet logger. |

All scripts automatically pull device credentials from `data/config.json` via [`tools/_config.py`](tools/_config.py) or fall back to standard environment variables (`DEVICE_MAC`, `LOCAL_KEY`, `DEVICE_UUID`, `DEVICE_ID`).

