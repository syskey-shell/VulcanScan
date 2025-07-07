import argparse
import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
import json
from datetime import datetime

init(autoreset=True)

try:
    import nmap
    nmap_available = True
except ImportError:
    nmap_available = False
    print(f"{Fore.RED}[!] python-nmap not found. Only socket scan will work.{Style.RESET_ALL}")

open_ports = []

def print_banner():
    banner = f"""
{Fore.GREEN} __     __         _                  _____                                  
{Fore.GREEN} \\ \\   / /        | |                / ____|                                 
{Fore.GREEN}  \\ \\_/ /__  _   _| | ___  ___ ___  | (___   ___ __ _ _ __  _ __   ___ _ __  
{Fore.GREEN}   \\   / _ \\| | | | |/ _ \\/ __/ __|  \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__| 
{Fore.GREEN}    | | (_) | |_| | |  __/\\__ \\__ \\  ____) | (_| (_| | | | | | | |  __/ |    
{Fore.GREEN}    |_|\\___/ \\__,_|_|\\___||___/___/ |_____/ \\___\\__,_|_| |_|_| |_|\\___|_|   
                                                                                 
{Fore.GREEN}                        [ VulcanScan Beast One ]                               
    """
    print(banner + Style.RESET_ALL)

def grab_banner(sock):
    try:
        return sock.recv(1024).decode().strip()
    except:
        return "No banner"

def scan_port(target, port, verbose=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        result = s.connect_ex((target, port))
        if result == 0:
            banner = grab_banner(s)
            print(f"{Fore.GREEN}[+] {target} Port {port}: OPEN - Banner: {banner}{Style.RESET_ALL}")
            open_ports.append({"host": target, "port": port, "banner": banner, "timestamp": datetime.now().isoformat()})
        elif verbose:
            print(f"{Fore.RED}[-] {target} Port {port}: CLOSED{Style.RESET_ALL}")
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}[!] Error scanning {target}:{port} -> {e}{Style.RESET_ALL}")
    finally:
        s.close()

def basic_port_scanner(target, start_port, end_port, verbose=False):
    print(f"\n[Socket Scan] Scanning {target} from port {start_port} to {end_port}...")
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, target, port, verbose)

def nmap_scan(target, start_port, end_port):
    if not nmap_available:
        print(f"{Fore.RED}[!] Skipping Nmap scan (python-nmap not installed){Style.RESET_ALL}")
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
            for entry in open_ports:
                f.write(f"{entry['host']}:{entry['port']} OPEN - Banner: {entry['banner']} - Time: {entry['timestamp']}\n")
        with open("results.json", 'w') as jf:
            json.dump(open_ports, jf, indent=4)
        print(f"[+] Results saved to {output_file} and results.json")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="VulcanScan Beast One: Advanced Python Port Scanner")
    parser.add_argument("-t", "--targets", help="Comma-separated target hosts", required=True)
    parser.add_argument("-sp", "--startport", type=int, help="Start port", required=True)
    parser.add_argument("-ep", "--endport", type=int, help="End port", required=True)
    parser.add_argument("-o", "--output", help="Output file (optional)")
    parser.add_argument("-v", "--verbose", help="Verbose mode shows closed ports and errors", action="store_true")
    args = parser.parse_args()

    hosts = [h.strip() for h in args.targets.split(",")]
    start_port = args.startport
    end_port = args.endport
    output_file = args.output

    try:
        for target in hosts:
            basic_port_scanner(target, start_port, end_port, args.verbose)
            nmap_scan(target, start_port, end_port)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user.{Style.RESET_ALL}")
    finally:
        save_results(output_file)

if __name__ == "__main__":
    main()


