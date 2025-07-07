##  About VulcanScan

VulcanScan is a beginner-friendly but powerful Python port scanner for penetration testers, bug bounty hunters, and security learners.  
It’s fast, multi-threaded, and gives you clean, colorful output with banners and JSON logs.

I built this as an aspiring penetration tester to help newbies learn how scanning works under the hood 
not just to run tools, but to build them, break them, and really understand them.  
This is your first custom recon tool tweak it, test it, and make it your own!

---

## Features

✅ Multi-threaded scanning — fast on big ranges  
✅ Color output: green for open ports, red for closed/errors  
✅ Banner grabbing for open ports  
✅ JSON output with timestamps for easy reporting  
✅ Verbose mode to show closed ports too  
✅ Optional Nmap fallback scan  
✅ ASCII banner — your signature as a builder

---

## Installation

1️⃣ Clone this repository:

git clone https://github.com/syskey-shell/VulcanScan
cd VulcanScan

2️⃣ Install requirements:

pip install -r requirements.txt

---

## Usage (Quick Tutorial)

Basic example:

python VulcanScan_2.0.py -t 192.168.1.1,example.com -sp 1 -ep 1000 -o results.txt -v

Flags:
- -t : Comma-separated target hosts/IPs
- -sp : Start port
- -ep : End port
- -o : Output file name (optional)
- -v : Verbose mode to show closed ports (optional)

---

##  Example Output

[+] 192.168.1.1 Port 22: OPEN - Banner: OpenSSH 7.4
\\x1b[91m[-] 192.168.1.1 Port 21: CLOSED\\x1b[0m
[+] Results saved to results.txt and results.json

---

##  About Me

I’m syskey, an aspiring penetration tester and security enthusiast.  
I believe in learning by building this tool is open source so other beginners can learn too.  
I love practical projects that prove I know my basics and can turn ideas into working tools.

---

## Disclaimer

Use VulcanScan responsibly! This tool is for educational and authorized testing only always get proper permission before scanning any network.  
Remember using this tool for illegal or unethical hacking is just asking for trouble (and maybe prison).  
I’m not responsible for any misuse you’ve been warned! 😉

---

##  License

Licensed under the Apache License 2.0 — see the LICENSE for details.

---

## Author

syskey — https://github.com/syskey-shell  
Connect if you find this helpful!
discord = __syskey


