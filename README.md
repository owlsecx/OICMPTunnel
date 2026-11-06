# 🦉 OICMPTunnel

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Network%20/%20DNS-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OICMPTunnel** — ICMP/ICMPv6 covert-channel & tunnel detector (offline; pcap/log) ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OICMPTunnel is an offline-first OwlSec tool for ICMP/ICMPv6 covert-channel & tunnel detector (offline; pcap/log). It provides an interactive cyan terminal UI and a full CLI with multi-format export (TXT, Markdown, JSON, CSV, SARIF), designed for authorized security work on Linux.

---

## ✨ Features

- Detect ICMP/ICMPv6 covert channels and tunnels offline
- Analyze pcap/log inputs for payload abuse and beaconing
- Flag unusual sizes, sequences and request/reply patterns
- Safe detection workflow without generating attack traffic
- Severity grading and structured findings
- Export results for network detection engineering

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OICMPTunnel OICMPTunnel.go
./OICMPTunnel --help
./OICMPTunnel --input capture.pcap
./OICMPTunnel --input icmp.log --format json
./OICMPTunnel --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
