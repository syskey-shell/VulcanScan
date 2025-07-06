## About Me
My goal is to build more security tools.
I hope this project helps other beginners.. <3 :).

# Basic Python Port Scanner

This is a beginner friendly port scanner written in Python. It can scan multiple hosts and a range of ports using both basic socket programming and the "python-nmap" library.

## Features
- Scan multiple hosts (comma-separated IPs or domains)
- Scan a custom port range
- Uses socket scanning by default
- Uses Nmap scanning if the "python-nmap" library is installed
- Easy to use and extend for learning purposes

## Requirements
- Python 3.x
- (Optional) "python-nmap" library for advanced scanning

## Usage
Run the script in your terminal:
python "port_scanner.py"

You will be prompted to enter:
- Target hosts (comma-separated, e.g. "127.0.0.1, scanme.nmap.org")
- Start port (e.g. "1")
- End port (e.g. "1024")

The script will show open ports for each host using both socket and Nmap scanning (if available).

## Example Output
Enter target hosts (comma-separated IPs/domains): 127.0.0.1, scanme.nmap.org
Enter start port: 20
Enter end port: 25

[Socket Scan] Scanning 127.0.0.1 from port 20 to 25...
Port 22: OPEN
[Nmap Scan] Scanning 127.0.0.1 from port 20 to 25...
Host: 127.0.0.1 ()
State: up
Protocol: tcp
Port: 22	State: open
...


## Notes
- This script is for educational and ethical use only.
- Results may vary depending on your network and firewall settings.

## License
This project is open source and free to use for learning and ethical purposes.
