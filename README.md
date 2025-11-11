# Network Packet Sniffer (Python)

A lightweight packet capture tool to inspect Ethernet / IPv4 / TCP / UDP headers and analyze real-time packet flow.

## Features
- Parses Ethernet, IPv4, TCP, UDP headers
- Prints per-packet summary and periodic stats (packets per protocol, top source IPs)
- Optional JSONL logging of parsed records

## Requirements
- Linux (tested on Ubuntu)
- Python 3.8+
- Root privileges to run raw sockets

## Run
sudo python3 sniffer.py --iface eth0 --log packets.jsonl

## Notes
- This is a learning/demo tool (no reassembly, no pcap output). See improvements in README for next steps.
