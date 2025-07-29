import os
import time
import random
import json
import logging
from datetime import datetime

try:
    import colorama
    from colorama import Fore, Style
except ImportError:
    print("colorama module not found. Installing...")
    os.system("pip install colorama")
    import colorama
    from colorama import Fore, Style

colorama.init(autoreset=True)

LOGFILE = "iotbreaker_botnet_session.log"
logging.basicConfig(
    filename=LOGFILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- Data ---

vuln_database = {
    "firmware_1.bin": [
        {"name": "Hardcoded Credentials", "severity": "High", "description": "Detected hardcoded passwords in config files."},
        {"name": "Buffer Overflow", "severity": "Critical", "description": "Found vulnerable buffer overflow in HTTP server."}
    ],
    "firmware_2.bin": [
        {"name": "Outdated OpenSSL", "severity": "Medium", "description": "Firmware uses OpenSSL 1.0.1 which is vulnerable."}
    ]
}

exploit_kits = {
    "Hardcoded Credentials": ["Credential Leak Exploit", "Default Password Brute Force"],
    "Buffer Overflow": ["Remote Code Execution", "Denial of Service"],
    "Outdated OpenSSL": ["Heartbleed Exploit"]
}

attack_methods = {
    "udp": "UDP Flood",
    "tcp": "TCP Flood",
    "syn": "SYN Flood",
    "http": "HTTP GET Flood"
}

# Botnet Data Structure
class Bot:
    def __init__(self, ip, device, status="Online"):
        self.ip = ip
        self.device = device
        self.status = status
        self.infected = False
        self.uptime = 0
        self.last_seen = time.time()

    def update_uptime(self):
        self.uptime = int(time.time() - self.last_seen)

    def __str__(self):
        self.update_uptime()
        inf = Fore.GREEN + "Infected" if self.infected else Fore.RED + "Clean"
        return f"{self.ip} | {self.device} | Status: {self.status} | Uptime: {self.uptime}s | {inf}"

bots = []

# --- Helper Functions ---
def print_header():
    print(Fore.CYAN + "=" * 70)
    print(Fore.CYAN + "Welcome to IoT-Breaker Botnet Edition: Manage & Exploit IoT Devices")
    print(Fore.CYAN + "=" * 70 + "\n")

def slow_print(text, delay=0.03):
    for c in text:
        print(c, end='', flush=True)
        time.sleep(delay)
    print()

def input_int(prompt, min_val=None, max_val=None):
    while True:
        val = input(prompt)
        if val.isdigit():
            val_int = int(val)
            if (min_val is not None and val_int < min_val) or (max_val is not None and val_int > max_val):
                print(Fore.RED + f"Input must be between {min_val} and {max_val}.")
                continue
            return val_int
        else:
            print(Fore.RED + "Please enter a valid number.")

def simulate_progress_bar(duration=5, task="Processing"):
    print(f"{task}: ", end="")
    for _ in range(duration):
        print(Fore.GREEN + "█", end="", flush=True)
        time.sleep(1)
    print(" Done!")

def log_action(action):
    logging.info(action)

# --- Core Functionalities ---

def extract_firmware():
    slow_print("Step 1: Firmware Extraction\n")
    firmware_path = input("Enter the firmware file path to extract: ").strip()
    if not os.path.isfile(firmware_path):
        print(Fore.YELLOW + "Warning: File not found. Proceeding with simulated extraction.")
        firmware_name = os.path.basename(firmware_path)
    else:
        firmware_name = os.path.basename(firmware_path)
        slow_print(f"Found firmware file: {firmware_name}")

    slow_print("Starting extraction (using binwalk if installed)...")
    simulate_progress_bar(7, "Extracting firmware")

    extracted = True if random.random() > 0.1 else False
    if extracted:
        print(Fore.GREEN + f"Firmware extraction complete: extracted files saved to './extracted/{firmware_name}/'")
        log_action(f"Extracted firmware: {firmware_name}")
    else:
        print(Fore.RED + "Extraction failed due to corrupted file or unsupported format.")
        log_action(f"Failed extraction: {firmware_name}")
    return firmware_name if extracted else None

def scan_firmware(firmware_name):
    slow_print("\nStep 2: Vulnerability Scanning\n")
    if not firmware_name:
        print(Fore.RED + "No firmware extracted. Cannot scan vulnerabilities.\n")
        return []

    slow_print(f"Scanning extracted firmware '{firmware_name}' for vulnerabilities...")
    simulate_progress_bar(5, "Scanning")

    vulns = vuln_database.get(firmware_name, [])
    if not vulns:
        print(Fore.GREEN + "No vulnerabilities found in the firmware.\n")
        log_action(f"No vulnerabilities found in {firmware_name}")
    else:
        print(Fore.RED + f"Found {len(vulns)} vulnerability(ies):")
        for v in vulns:
            print(Fore.YELLOW + f"- {v['name']} | Severity: {v['severity']}")
            print(f"  Description: {v['description']}\n")
        log_action(f"Vulnerabilities found in {firmware_name}: {len(vulns)}")
    return vulns

def scan_network():
    slow_print("\nStep 3: Network Scanning\n")
    print("Starting network scan for IoT devices on your subnet...")
    simulate_progress_bar(5, "Scanning network")

    # Simulated devices found
    devices = [
        {"ip": "192.168.1.10", "device": "Smart Camera", "status": "Online"},
        {"ip": "192.168.1.23", "device": "Smart Thermostat", "status": "Online"},
        {"ip": "192.168.1.45", "device": "Smart Light Bulb", "status": "Offline"},
    ]
    print(Fore.GREEN + f"Found {len(devices)} device(s):")
    for d in devices:
        status_color = Fore.GREEN if d["status"] == "Online" else Fore.RED
        print(f"- IP: {d['ip']} | Device: {d['device']} | Status: {status_color}{d['status']}")
    log_action("Network scan completed")
    return devices

def infect_device(devices):
    slow_print("\nStep 4: Infect Device\n")
    online_devices = [d for d in devices if d["status"] == "Online"]

    if not online_devices:
        print(Fore.RED + "No online devices available for infection.\n")
        return

    print("Online devices available to infect:")
    for idx, dev in enumerate(online_devices, 1):
        print(f"{idx}. {dev['ip']} | {dev['device']}")

    choice = input_int("Choose a device to infect (number): ", 1, len(online_devices))
    selected = online_devices[choice-1]

    # Check if already infected
    for bot in bots:
        if bot.ip == selected["ip"]:
            print(Fore.YELLOW + f"Device {selected['ip']} is already infected and part of your botnet.\n")
            return

    new_bot = Bot(selected["ip"], selected["device"])
    new_bot.infected = True
    bots.append(new_bot)
    print(Fore.GREEN + f"Device {selected['ip']} infected successfully and added to botnet.\n")
    log_action(f"Infected device: {selected['ip']}")

def show_bots():
    slow_print("\nBotnet Devices\n")
    if not bots:
        print(Fore.YELLOW + "No bots currently in your botnet.\n")
        return
    for bot in bots:
        print(bot)
    log_action("Displayed botnet devices")

def launch_attack():
    slow_print("\nStep 5: Launch Attack\n")
    if not bots:
        print(Fore.RED + "Your botnet is empty! Infect devices first.\n")
        return

    print("Available attack methods:")
    for key, val in attack_methods.items():
        print(f"- {key}: {val}")

    method = input("Choose attack method (udp/tcp/syn/http): ").lower()
    if method not in attack_methods:
        print(Fore.RED + "Invalid attack method selected.\n")
        return

    target_ip = input("Enter the target IP address: ").strip()
    duration = input_int("Enter attack duration (seconds): ", 1, 3600)

    slow_print(f"Launching {attack_methods[method]} attack against {target_ip} for {duration} seconds...")
    simulate_progress_bar(min(duration, 10), f"Attacking {target_ip}")

    # Simulate attack success
    success = random.random() > 0.2
    if success:
        print(Fore.GREEN + f"Attack on {target_ip} completed successfully!\n")
        log_action(f"Launched {attack_methods[method]} attack on {target_ip} for {duration}s")
    else:
        print(Fore.RED + "Attack failed due to network defenses.\n")
        log_action(f"Attack failed on {target_ip}")

def generate_report(firmware_name, vulnerabilities, devices):
    slow_print("\nStep 6: Report Generation\n")
    report = {
        "firmware": firmware_name,
        "timestamp": datetime.now().isoformat(),
        "vulnerabilities_found": vulnerabilities,
        "network_devices": devices,
        "botnet_devices": [{"ip": b.ip, "device": b.device, "status": b.status, "infected": b.infected, "uptime": b.uptime} for b in bots]
    }
    filename = f"iotbreaker_botnet_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    print(Fore.GREEN + f"Report saved as '{filename}'\n")
    log_action(f"Report generated: {filename}")

def show_help():
    help_text = """
IoT-Breaker Botnet Edition Help Menu:
1. Extract Firmware: Select and extract firmware files for analysis.
2. Scan Firmware: Analyze firmware for known vulnerabilities.
3. Scan Network: Discover IoT devices on your local network.
4. Infect Device: Infect an online device to add it to your botnet.
5. Show Botnet Devices: List all infected devices under your control.
6. Launch Attack: Use your botnet to launch simulated attacks on a target.
7. Generate Report: Save all current data and botnet status to a JSON report.
8. Help: Show this help menu.
9. Exit: Quit the program.

Note: This is a simulation for educational purposes only.
"""
    print(Fore.CYAN + help_text)

def main():
    firmware_name = None
    vulnerabilities = []
    devices = []

    print_header()
    show_help()

    while True:
        choice = input_int(Fore.MAGENTA + "\nChoose an option (1-9): ", 1, 9)

        if choice == 1:
            firmware_name = extract_firmware()
        elif choice == 2:
            vulnerabilities = scan_firmware(firmware_name)
        elif choice == 3:
            devices = scan_network()
        elif choice == 4:
            infect_device(devices)
        elif choice == 5:
            show_bots()
        elif choice == 6:
            launch_attack()
        elif choice == 7:
            generate_report(firmware_name, vulnerabilities, devices)
        elif choice == 8:
            show_help()
        elif choice == 9:
            print(Fore.CYAN + "Thank you for using IoT-Breaker Botnet Edition! Goodbye.\n")
            break

if __name__ == "__main__":
    main()
