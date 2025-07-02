# 🔐 Networking & Security Practice Projects

Welcome! This repository is where I explore and practice the fundamentals and deeper concepts of **networking**, **security**, and everything in between.

Here you'll find a growing collection of hands-on scripts, tools, and analysis experiments that help me learn how networks work, how they're attacked, and how to defend them.

---

## 🧠 What You'll Find Here

This repo includes small, focused projects that cover topics like:

- 🔍 **Log analysis** (detecting suspicious activity in web server logs)  
- 🛡️ **Security patterns** and detection logic (burst access, external IP scans, etc.)  
- 📜 **Regex parsing** of common log formats  
- 🌐 **Network behavior analysis** tools  
- 🧪 Other experiments as I continue learning

Each project is self-contained and includes documentation and comments to explain what's going on.

---

## 📁 Current Project Highlight

### `suspicious_log_check.py`

A Python script that scans `web_activity.log` files. This was inspired by the Deloitte Cybersecurity Job simulation. The aim of the script is to:

- Detect wildcard queries
- Identify burst access attempts
- Check for suspicious factory scans
- Flag activity from external IP addresses

It also logs unmatched entries for future debugging. It’s lightweight and built for learning, but could be extended into a real-world tool.

---

## 🛠️ Why This Repo Exists

I'm learning by doing.

While reading and watching tutorials is great, I believe the best way to understand networking and security is to **build tools, break things, and fix them**. This repo reflects my journey through that process, and maybe it'll help others doing the same.

---

## 🚀 How to Use

You can clone this repo and run any script locally:

```bash
git clone https://github.com/AuntyyWonks/network-security.git
cd network-security
python suspicious_log_check.py
```
---

## 📌 Future Projects
Coming soon (or eventually 😅):

- ✳️ Packet sniffers using scapy
- 🌐 Network mapping scripts
- 🧰 Simple firewall or IDS mockups
- 🔐 Vulnerability scanners for practice

## 🤝 Contributions
This is a personal learning repo, but if you spot something broken or have an idea to improve one of the tools, feel free to open an issue

xoxo
yt.bloom
