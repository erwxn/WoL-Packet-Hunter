# 🪄 Magic Packet Sniffer (WoL Sensor)

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Scapy](https://img.shields.io/badge/Network-Scapy-orange?style=for-the-badge)
![UI](https://img.shields.io/badge/CLI-Rich-purple?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

## 📌 Project Overview
The **Magic Packet Sniffer** is a lightweight, real-time network sensor built in Python. It passively monitors local network traffic to detect, extract, and log Wake-on-LAN (WoL) "Magic Packets." 

In an enterprise or lab environment, this tool acts as a network tripwire to detect unauthorized remote-boot attempts, or as a diagnostic tool to debug complex network routing rules where UDP broadcast packets are frequently dropped.

## 🛠️ Key Features
* **Deep Packet Inspection:** Utilizes `scapy` to dissect raw network frames and analyze payload structures in real-time.
* **Protocol-Agnostic Signature Detection:** Hunts for the strict mathematical signature of a Magic Packet (6 bytes of `0xFF` followed by 16 repetitions of the target MAC address) regardless of the encapsulating protocol (UDP, TCP, or Raw).
* **Rich CLI UI:** Employs the `rich` library to generate clean, color-coded, and highly readable terminal alerts for immediate incident awareness.

---

## ⚙️ Prerequisites & Installation

This project requires Python 3 and elevated privileges to listen to raw network sockets.

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/Magic-Packet-Sniffer.git](https://github.com/YOUR_USERNAME/Magic-Packet-Sniffer.git)
   cd Magic-Packet-Sniffer

```

2. **Install the dependencies:**
```bash
pip install scapy rich

```


*(Alternatively, run `pip install -r requirements.txt` if provided).*

---

## 🚀 Usage Guide

Because the script interacts with raw network interfaces, it must be run with Administrator or Root privileges.

**On Linux / macOS:**

```bash
sudo python wol_sniffer.py

```

**On Windows:**
Open Command Prompt or PowerShell as **Administrator** and run:

```cmd
python wol_sniffer.py

```

### 📡 What to Expect

Once running, the sensor silently monitors the network. When a WoL broadcast is detected, it intercepts the packet, extracts the target MAC address, and displays a formatted alert:

```text
╭───────────────────────────────────────────────╮
│ ✨ MAGIC PACKET DETECTED ✨                   │
│ Target MAC: AA:BB:CC:DD:EE:FF                 │
│ Source: 192.168.1.50 (UDP)                    │
╰───────────────────────────────────────────────╯

```

---

## Use Cases

* **Blue Team / SOC:** Monitor internal VLANs for unexpected WoL broadcasts that could indicate lateral movement or unauthorized waking of dormant servers.
* **Network Administration:** Verify that directed broadcasts are properly traversing routers and firewalls to their intended subnets.
* **IoT Automation:** Can be modified to trigger local bash scripts or webhooks when a specific MAC address is targeted, acting as a secret, passwordless network trigger.

```
rements.txt` file next, or are you ready to push this straight to your GitHub?

```
