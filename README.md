##  About VulcanScan
VulcanScan is a beginner friendly but now more advanced Python port scanner and mini recon toolkit for penetration testers, bug bounty hunters, and security learners.
It’s still fast, multi-threaded, and gives you clean, colorful output  but now includes service detection, optional OSINT info(IP lookup, Reverse DNS, WHOIS).

I built this as an aspiring penetration tester to help newbies learn how real scanning works under the hood not just run tools, but build them, extend them, and understand how attackers map targets.
This is your first custom recon beast  tweak it, test it, break it, and make it your own.

---

## Features

Multi-threaded scanning — fast on big ranges  
Color output: green for open, red for closed/errors  
Banner grabbing for open ports  
Optional OSINT info gathering (IP lookup, Reverse DNS, WHOIS)  
JSON output with timestamps for reports  
Verbose mode to show closed ports too  
Optional Nmap fallback scan
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

Run with OSINT + Web Recon:

python VulcanScan.py -t 192.168.1.1,example.com -sp 1 -ep 1000 --osint --web-recon -o results.txt -v


| Flag      | Description                                                          |
|-----------|----------------------------------------------------------------------|
| `-t`      | Comma-separated target hosts/IPs                                     |
| `-sp`     | Start port                                                           |
| `-ep`     | End port                                                             |
| `-o`      | Output file name (optional)                                          |
| `-v`      | Verbose mode shows closed ports and errors (optional)                |
| `--osint` | Run basic OSINT info gathering (IP, Reverse DNS, WHOIS) (optional)   |


---

##  Example Output

[+] 192.168.1.1 Port 80: OPEN - Banner: Apache/2.4.7
[+] HTTP Response Headers: {...}
[+] Found: /admin [200]
[+] IP: 192.168.1.1 | Reverse DNS: ('example.local', [], ['192.168.1.1'])
[+] Results saved to results.txt and results.json
---

##  About Me

I’m syskey, an aspiring penetration tester and security enthusiast.  
I believe in learning by building this tool is open source so other beginners can learn too.  
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


