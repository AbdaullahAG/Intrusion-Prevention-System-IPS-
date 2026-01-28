
Snort 3 IPS: Transparent Bridge Implementation
A professional implementation of an Intrusion Prevention System (IPS) using Snort 3 in Inline Mode. This project demonstrates how to build a transparent network bridge that intercepts, analyzes, and drops malicious traffic (ICMP Floods, Nmap Scans) in real-time with negligible latency.

🚀 Overview
Unlike traditional IDS systems that only alert, this implementation acts as an active gatekeeper. By leveraging the DAQ (Data Acquisition) AFPacket module, Snort 3 sits directly in the traffic path between an attacker and a victim, providing proactive defense.

Key Features
Inline Prevention: Active packet dropping using drop rules.

Transparent Bridging: Stealth deployment without IP addresses on the bridge interfaces.

Kernel Leakage Fix: Optimized kernel settings to ensure 100% of traffic passes through the Snort engine.

Low Latency: High-performance processing with ~2ms overhead.

🏗️ System Architecture
The setup consists of a three-node virtual environment:

Attacker: Kali Linux (Generating malicious traffic).

IPS Bridge: Snort 3 engine bridging eth0 and eth1.

Victim: Target server (Protected asset).

Traffic Flow: Attacker ➔ [eth0 (Ingress) -> Snort 3 -> eth1 (Egress)] ➔ Victim

🛠️ Installation & Setup
1. Prerequisites
Ensure you have Snort 3 and LibDAQ installed.

sudo apt update && sudo apt install snort3

2. Network Interface Configuration
Flush IPs to prepare the interfaces for bridging:

sudo ip addr flush dev eth0
sudo ip addr flush dev eth1
sudo ip link set eth0 up
sudo ip link set eth1 up
sudo sysctl -w net.ipv4.ip_forward=0

3. Execution
Run Snort in Inline Mode:

sudo snort -Q --daq afpacket -i eth0:eth1 -c /etc/snort/snort.lua -A alert_fast --daq-var replace=1

🛡️ Sample IPS Rules
Located in local.rules:

Block Ping: drop icmp any any -> any any (msg:"ICMP Blocked"; sid:1000001;)

Block Nmap Scan: drop tcp any any -> any 22 (flags:S; msg:"SSH Scan Blocked"; detection_filter: track by_src, count 5, seconds 60; sid:1000007;)

📊 Performance Testing
Attack Scenario

Before IPS

After IPS

Result

ICMP Flood

Successful

100% Loss

Blocked

Nmap Stealth

Port Open

Filtered

Hidden
