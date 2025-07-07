import argparse
import socket
from concurrent.futures import ThreadPoolExecutor

try:
    import nmap
    nmap_available = True
except ImportError:
    nmap_available = False
    print("[!] python-nmap not found. Only socket scan will work.")

open_ports = []

def print_banner():
    banner = r"""
 __     __         _                  _____                                  
 \ \   / /        | |                / ____|                                 
  \ \_/ /__  _   _| | ___  ___ ___  | (___   ___ __ _ _ __  _ __   ___ _ __  
   \   / _ \| | | | |/ _ \/ __/ __|  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__| 
    | | (_) | |_| | |  __/\__ \__ \  ____) | (_| (_| | | | | | | |  __/ |    
    |_|\___/ \__,_|_|\___||___/___/ |_____/ \___\__,_|_| |_|_| |_|\___|_|    
                                                                              
                            [ VulcanScan v2.0 ]                               
    """
    print(banner)

def grab_banner(sock):
    try:
        return sock.recv(1024).decode().strip()
    except:
        return "No banner"

def scan_port(target, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        result = s.connect_ex((target, port))
        if result == 0:
            banner = grab_banner(s)
            print(f"[+] {target} Port {port}: OPEN - Banner: {banner}")
            open_ports.append((target, port, banner))
    except Exception:
        pass
    finally:
        s.close()

def basic_port_scanner(target, start_port, end_port):
    print(f"\n[Socket Scan] Scanning {target} from port {start_port} to {end_port}...")
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, target, port)

def nmap_scan(target, start_port, end_port):
    if not nmap_available:
        print("[!] Skipping Nmap scan (python-nmap not installed)")
        return
    print(f"\n[Nmap Scan] Scanning {target} from port {start_port} to {end_port}...")
    nm = nmap.PortScanner()
    try:
        scan_range = f"{start_port}-{end_port}"
        nm.scan(target, scan_range)
        for host in nm.all_hosts():
            print(f"Host: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    state = nm[host][proto][port]['state']
                    print(f"Port: {port}\tState: {state}")
    except Exception as e:
        print(f"Error running python-nmap scan: {e}")

def save_results(output_file):
    if output_file:
        with open(output_file, 'w') as f:
            for host, port, banner in open_ports:
                f.write(f"{host}:{port} OPEN - Banner: {banner}\n")
        print(f"[+] Results saved to {output_file}")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="VulcanScan: Improved Python Port Scanner")
    parser.add_argument("-t", "--targets", help="Comma-separated target hosts", required=True)
    parser.add_argument("-sp", "--startport", type=int, help="Start port", required=True)
    parser.add_argument("-ep", "--endport", type=int, help="End port", required=True)
    parser.add_argument("-o", "--output", help="Output file (optional)")
    args = parser.parse_args()

    hosts = [h.strip() for h in args.targets.split(",")] 
    start_port = args.startport
    end_port = args.endport
    output_file = args.output

    try:
        for target in hosts:
            basic_port_scanner(target, start_port, end_port)
            nmap_scan(target, start_port, end_port)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    finally:
        save_results(output_file)

if __name__ == "__main__":
    main()
