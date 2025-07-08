import ctypes
import sys
import os
import subprocess
import winreg as reg
import uuid
import random
import string
import shutil
from datetime import datetime

# --- Constants and Configuration ---
LOG_FILE = "spoofer_log.txt"
BACKUP_FILE = "registry_backup.reg"

# --- Core Functions ---

def is_admin():
    """Checks if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def log_change(message):
    """Logs a message to the log file with a timestamp."""
    with open(LOG_FILE, "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")
    print(message)

def backup_registry_key(key_path, value_name):
    """Exports a specific registry key value to a .reg backup file before changing it."""
    try:
        # This is a simplified backup. For a full key backup, we'd export the whole branch.
        # For this script, we'll just note the value in a text-based format.
        root_key_str, sub_key_path = key_path.split('\\', 1)
        root_key = getattr(reg, root_key_str)
        
        with reg.OpenKey(root_key, sub_key_path, 0, reg.KEY_READ) as key:
            value, _ = reg.QueryValueEx(key, value_name)
            with open(BACKUP_FILE, "a") as f:
                f.write(f"[{key_path}]\n")
                f.write(f'"{value_name}"="{value}"\n\n')
            return True
    except Exception as e:
        log_change(f"[ERROR] Could not back up registry value {key_path}\\{value_name}: {e}")
        return False

def generate_random_string(length):
    """Generates a random alphanumeric string."""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_random_mac():
    """Generates a random, valid MAC address string (no separators)."""
    return ''.join(random.choices(string.hexdigits.upper(), k=12))

def run_command(command, shell=True):
    """Runs a command and logs its output."""
    try:
        log_change(f"Running command: {command}")
        result = subprocess.run(command, shell=shell, check=True, capture_output=True, text=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)
        if result.stdout:
            log_change(f"Command output: {result.stdout.strip()}")
        if result.stderr:
            log_change(f"Command error output: {result.stderr.strip()}")
    except subprocess.CalledProcessError as e:
        log_change(f"[ERROR] Command '{command}' failed with exit code {e.returncode}")
        if e.stderr:
            log_change(f"Stderr: {e.stderr.strip()}")
    except Exception as e:
        log_change(f"[ERROR] Failed to run command '{command}': {e}")

# --- Spoofing Functions ---

def spoof_disk_serials():
    log_change("--- Starting Disk Spoofing ---")
    # This is a complex operation. We'll simulate by targeting identifiers in the registry.
    # A true low-level spoofer would require a kernel driver.
    try:
        scsi_path = r"SYSTEM\CurrentControlSet\Enum\SCSI"
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, scsi_path) as scsi_key:
            for i in range(reg.QueryInfoKey(scsi_key)[0]):
                disk_key_name = reg.EnumKey(scsi_key, i)
                if "Disk" in disk_key_name:
                    with reg.OpenKey(scsi_key, disk_key_name) as disk_key:
                        for j in range(reg.QueryInfoKey(disk_key)[0]):
                            instance_key_name = reg.EnumKey(disk_key, j)
                            instance_path = f"{scsi_path}\\{disk_key_name}\\{instance_key_name}"
                            with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, instance_path, 0, reg.KEY_WRITE) as instance_key:
                                new_serial = generate_random_string(10)
                                reg.SetValueEx(instance_key, "Device Parameters\\Disk\\SerialNumber", 0, reg.REG_SZ, new_serial)
                                log_change(f"Spoofed serial for {instance_key_name} to {new_serial}")
    except Exception as e:
        log_change(f"[ERROR] Disk spoofing failed: {e}")

def spoof_guids_and_bios():
    log_change("--- Starting GUID & BIOS Spoofing ---")
    guid_paths = {
        "HwProfileGuid": r"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001",
        "MachineGuid": r"SOFTWARE\Microsoft\Cryptography",
        "MachineId": r"SOFTWARE\Microsoft\SQMClient"
    }
    for name, path in guid_paths.items():
        try:
            with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path, 0, reg.KEY_WRITE) as key:
                new_guid = "{" + str(uuid.uuid4()) + "}"
                backup_registry_key(f"HKEY_LOCAL_MACHINE\\{path}", name)
                reg.SetValueEx(key, name, 0, reg.REG_SZ, new_guid)
                log_change(f"Spoofed {name} to {new_guid}")
        except Exception as e:
            log_change(f"[ERROR] Failed to spoof {name}: {e}")
    # BIOS Date Spoofing
    try:
        bios_path = r"HARDWARE\DESCRIPTION\System\BIOS"
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, bios_path, 0, reg.KEY_WRITE) as key:
            new_date = f"{random.randint(1, 12):02d}/{random.randint(1, 28):02d}/{random.randint(2018, 2023)}"
            backup_registry_key(f"HKEY_LOCAL_MACHINE\\{bios_path}", "BIOSReleaseDate")
            reg.SetValueEx(key, "BIOSReleaseDate", 0, reg.REG_SZ, new_date)
            log_change(f"Spoofed BIOSReleaseDate to {new_date}")
    except Exception as e:
        log_change(f"[ERROR] Failed to spoof BIOS date: {e}")

def spoof_pc_name():
    log_change("--- Starting PC Name Spoofing ---")
    new_name = "DESKTOP-" + generate_random_string(7)
    paths = [
        r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
        r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    ]
    value_names = ["ComputerName", "Hostname", "NV Hostname"]
    try:
        for path in paths:
            for name in value_names:
                try:
                    with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path, 0, reg.KEY_WRITE) as key:
                        backup_registry_key(f"HKEY_LOCAL_MACHINE\\{path}", name)
                        reg.SetValueEx(key, name, 0, reg.REG_SZ, new_name)
                        log_change(f"Set {name} in {path} to {new_name}")
                except FileNotFoundError:
                    continue # Not all keys have all value names
        log_change(f"PC Name successfully spoofed to: {new_name}")
    except Exception as e:
        log_change(f"[ERROR] PC Name spoofing failed: {e}")

def spoof_mac_address():
    log_change("--- Starting MAC Address Spoofing ---")
    try:
        net_class_key_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, net_class_key_path) as net_class_key:
            for i in range(20):
                try:
                    adapter_key_name = reg.EnumKey(net_class_key, i)
                    adapter_path = f"{net_class_key_path}\\{adapter_key_name}"
                    with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, adapter_path, 0, reg.KEY_WRITE) as adapter_key:
                        try:
                            driver_desc, _ = reg.QueryValueEx(adapter_key, "DriverDesc")
                            new_mac = generate_random_mac()
                            backup_registry_key(f"HKEY_LOCAL_MACHINE\\{adapter_path}", "NetworkAddress")
                            reg.SetValueEx(adapter_key, "NetworkAddress", 0, reg.REG_SZ, new_mac)
                            log_change(f"Spoofed MAC for '{driver_desc}' to {new_mac}")
                            # Disable/Enable to apply changes
                            run_command(f'netsh interface set interface name="{driver_desc}" admin=disabled')
                            run_command(f'netsh interface set interface name="{driver_desc}" admin=enabled')
                        except FileNotFoundError:
                            continue
                except OSError:
                    break
    except Exception as e:
        log_change(f"[ERROR] MAC spoofing failed: {e}")

def spoof_smbios():
    log_change("--- Starting SMBIOS Spoofing ---")
    smbios_path = r"SYSTEM\CurrentControlSet\Control\SystemInformation"
    try:
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, smbios_path, 0, reg.KEY_WRITE) as key:
            new_serial = generate_random_string(20)
            backup_registry_key(f"HKEY_LOCAL_MACHINE\\{smbios_path}", "SystemSerialNumber")
            reg.SetValueEx(key, "SystemSerialNumber", 0, reg.REG_SZ, new_serial)
            log_change(f"Spoofed SystemSerialNumber to {new_serial}")
    except Exception as e:
        log_change(f"[ERROR] SMBIOS spoofing failed: {e}")
        
def spoof_product_id():
    log_change("--- Starting Product ID Spoofing ---")
    prod_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    try:
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, prod_path, 0, reg.KEY_WRITE) as key:
            # Format: XXXXX-XXXXX-XXXXX-XXXXX
            new_id = f"{generate_random_string(5)}-{generate_random_string(5)}-{generate_random_string(5)}-{generate_random_string(5)}"
            backup_registry_key(f"HKEY_LOCAL_MACHINE\\{prod_path}", "ProductId")
            reg.SetValueEx(key, "ProductId", 0, reg.REG_SZ, new_id)
            log_change(f"Spoofed ProductId to {new_id}")
    except Exception as e:
        log_change(f"[ERROR] Product ID spoofing failed: {e}")

# --- Cleaner Functions ---

def clean_cache(name, paths):
    log_change(f"--- Cleaning {name} Cache ---")
    for path in paths:
        full_path = os.path.expandvars(path)
        if os.path.exists(full_path):
            try:
                shutil.rmtree(full_path, ignore_errors=True)
                log_change(f"Removed {full_path}")
            except Exception as e:
                log_change(f"[ERROR] Failed to remove {full_path}: {e}")
        else:
            log_change(f"Path not found, skipping: {full_path}")

def sechex_cleaner():
    log_change("--- Running SecHex Comprehensive Cleaner ---")
    # 1. Flush DNS
    run_command("ipconfig /flushdns")
    # 2. Clean Temp Folders
    clean_cache("Temp Folders", ["%temp%", r"C:\Windows\Temp", "%userprofile%\\Recent"])
    # 3. TCP Reset
    run_command("netsh int ip reset")
    run_command("netsh winsock reset")
    # 4. Kill Anti-Cheat Processes (example list)
    ac_processes = ["faceit.exe", "vgc.exe", "vgtray.exe", "rzanting.exe", "anticheat.exe", "BattleEye.exe", "BEservice.exe"]
    for proc in ac_processes:
        run_command(f"taskkill /f /im {proc}")
    # 5. Clean Game Caches
    clean_ubisoft_cache()
    clean_valorant_cache()
    log_change("--- SecHex Cleaner Finished ---")

def clean_ubisoft_cache():
    clean_cache("Ubisoft", [r"%LOCALAPPDATA%\Ubisoft Game Launcher"])

def clean_valorant_cache():
    clean_cache("Valorant/Riot", [r"%LOCALAPPDATA%\Riot Games"])

# --- Utility Functions ---

def get_system_info():
    log_change("--- Gathering System Information ---")
    info_commands = {
        "System Info": "systeminfo",
        "Disk Info": "wmic diskdrive get model,serialnumber",
        "CPU Info": "wmic cpu get name, L2cachesize, L3cachesize",
        "GPU Info": "wmic path win32_videocontroller get name",
        "Network Info": "ipconfig /all"
    }
    for name, cmd in info_commands.items():
        log_change(f"\n--- {name} ---")
        run_command(cmd)

def check_registry():
    log_change("--- Running Registry Checker ---")
    keys_to_check = [
        r"SYSTEM\CurrentControlSet\Enum\SCSI",
        r"SOFTWARE\Microsoft\Cryptography",
        r"SYSTEM\CurrentControlSet\Control\SystemInformation"
    ]
    missing = []
    for path in keys_to_check:
        try:
            with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path):
                pass
        except FileNotFoundError:
            missing.append(path)
    if missing:
        log_change("[ERROR] Missing critical registry keys:")
        for m in missing:
            log_change(f"  - {m}")
    else:
        log_change("[SUCCESS] All critical registry keys found.")

def explain_kernel_integration():
    print("""
    if u do this u might be cooked
    """)

# --- Main Menu ---

def print_menu():
    print("\n" + "="*25 + " HWID Spoofer & Utility " + "="*25)
    print(" [1] All In One (Spoof & Clean) - Type '1' or 'A'")
    print(" [2] Spoof PC Identifiers (GUIDs, PC Name, ProductID, etc.)")
    print(" [3] Spoof Hardware (Disk, MAC, SMBIOS)")
    print(" [4] Run SecHex Comprehensive Cleaner")
    print(" [5] Clean Specific Caches (Ubisoft/Valorant)")
    print(" [6] Run System Utilities (Info, Registry Check)")
    print(" [7] Explain Kernel Integration")
    print(" [0] Exit")
    print("="*72)

def main():
    if not is_admin():
        print("[FATAL] Administrator privileges are required. Please re-run as admin.")
        sys.exit()

    # Initialize log and backup files
    with open(BACKUP_FILE, "w") as f:
        f.write("Windows Registry Editor Version 5.00\n\n")
    log_change("Script started. Logging and backups are active.")

    while True:
        print_menu()
        choice = input("Enter your choice: ")
        if choice == '1' or choice.upper() == 'A':
            spoof_guids_and_bios()
            spoof_pc_name()
            spoof_product_id()
            spoof_disk_serials()
            spoof_mac_address()
            spoof_smbios()
            sechex_cleaner()
            log_change("--- spoof done yay ---")
            print("\n[NOTE] A system RESTART is required for all changes to take full effect.")
        elif choice == '2':
            spoof_guids_and_bios()
            spoof_pc_name()
            spoof_product_id()
        elif choice == '3':
            spoof_disk_serials()
            spoof_mac_address()
            spoof_smbios()
        elif choice == '4':
            sechex_cleaner()
        elif choice == '5':
            clean_ubisoft_cache()
            clean_valorant_cache()
        elif choice == '6':
            get_system_info()
            check_registry()
        elif choice == '7':
            explain_kernel_integration()
        elif choice == '0':
            print("Exiting.")
            break
        else:
            print("dumbass pick a CORRECT number")
        input("\nPress Enter to return to the menu...")

if __name__ == "__main__":
    main()
