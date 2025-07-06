import socket
try:
    import nmap
    nmap_available = True
except ImportError:
    nmap_available = False
    print("[!] python-nmap library not found. Only socket scan will be used.\nInstall it with: pip install python-nmap\n")

def basic_port_scanner(target, start_port, end_port):
    print(f"\n[Socket Scan] Scanning {target} from port {start_port} to {end_port}...")
    for port in range(start_port, end_port + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"Port {port}: OPEN")
            s.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")

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

if __name__ == "__main__":
    hosts = input("Enter target hosts (comma-separated IPs/domains): ").split(",")
    hosts = [h.strip() for h in hosts if h.strip()]
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
    for target in hosts:
        basic_port_scanner(target, start_port, end_port)
        nmap_scan(target, start_port, end_port)
