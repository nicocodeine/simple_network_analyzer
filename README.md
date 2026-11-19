# Simple Network Analyzer

A simple Python-based network protocol analyzer with packet capture, protocol detection, filtering and security alerts.

## Features

- Real-time packet capture using Scapy
- Simulation mode
- TCP, UDP, ICMP and other packet detection
- HTTP, HTTPS, DNS, SSH, FTP, TELNET, SMTP, DHCP and NTP detection
- Packet information and protocol analysis
- Packet filtering by protocol and alert severity
- Wireshark-inspired security alert colors
- Security warnings
- Packet Analysis panel
- Security Warnings panel
- Test packets for simulation mode

## Security Alerts

| Level | Description |
|---|---|
| LOW | Low-risk or informational traffic |
| MEDIUM | Traffic that should be reviewed |
| HIGH | Potentially risky services or network exposure |
| CRITICAL | Possible credential or authentication data exposure |

The analyzer can detect traffic related to Telnet, FTP, HTTP, SMTP, POP3, IMAP, SSH, DNS, DHCP, NTP, SNMP, SSDP/UPnP, NetBIOS, database services, remote desktop services and ICMP.

Large packets are classified as **LOW severity**.

## Requirements

- Python 3
- Scapy

Install Scapy:

```bash
pip install scapy
```

## Running from Python

```bash
python simple_network_analyzer.py
```

## Windows EXE

The repository also contains a pre-built Windows executable:

```text
SimpleNetworkAnalyzer.exe
```

The EXE can be used without manually running the Python source code.

## Project Structure

```text
simple-network-analyzer/
│
├── simple_network_analyzer.py
├── SimpleNetworkAnalyzer.exe
└── README.md
```

## Simulation Mode

If real packet capture cannot be started, the application switches to simulation mode and generates example packets for testing the analyzer and alert system.

## Disclaimer

This project is intended for educational and network-analysis purposes.

Only capture or analyze network traffic that you are authorized to inspect.

## Author

**nicocodeine**
