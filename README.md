# Basic Network Sniffer

A simple Python-based network sniffer that captures and analyzes network traffic. This project is designed to help you understand how data flows on a network and how network packets are structured.

---

## Table of Contents
1. [Overview](#overview)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Customization](#customization)

---

## Overview

This project uses the `scapy` library to capture and analyze network packets. It provides insights into the structure of Ethernet frames, IP packets, TCP/UDP segments, and raw payload data. It's a great tool for learning about network protocols and packet analysis.

---

## Features

- Captures network packets in real-time.
- Displays detailed information about Ethernet, IP, TCP, and UDP layers.
- Extracts and displays raw payload data.
- Supports filtering for specific types of traffic (e.g., TCP-only).
- Easy to customize and extend.

---

## Requirements

- Python 3.x
- `scapy` library
- Administrative privileges (for capturing network traffic)

---

## Installation

1. Clone the repository:
   ```bash
   https://github.com/Irrfan47/CodeAlpha_BasicNetworkSniffer.git
   cd basic-network-sniffer
2. Install the required dependencies:
   ```bash
   pip install scapy

---

## Usage

1. Run the network sniffer script:
   ```bash
   sudo python3 network_sniffer.py
2. The script will start capturing packets on the default network interface. You can specify a custom interface and the number of packets to capture by modifying the start_sniffer function in the script.
3. The captured packets will be displayed in the terminal with details about their structure.

---

## Customization

You can customize the sniffer to suit your needs:
- Filter specific traffic: Modify the sniff function to filter for specific protocols (e.g., TCP-only):
  ```bash
   sniff(iface=interface, prn=packet_callback, count=count, filter="tcp")
- Save packets to a file: Use scapy's wrpcap function to save captured packets for later analysis.
- Analyze higher-level protocols: Extend the script to decode and analyze protocols like HTTP, DNS, etc.
