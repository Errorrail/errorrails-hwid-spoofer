import tkinter as tk
from tkinter import ttk, scrolledtext, font
import ctypes
import sys
import os
import subprocess
import uuid
import random
import winreg as reg
import string
import shutil
from datetime import datetime
import threading

# --- Constants and Configuration ---
LOG_FILE = "spoofer_log.txt"
BACKUP_FILE = "registry_backup.reg"

# --- Core Functions (Original Script Logic) ---

def is_admin():
    """Checks if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def log_change(message):
    """Logs a message to the log file and prints to the UI's textbox."""
    with open(LOG_FILE, "a", encoding='utf-8') as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")
    # Printing to stdout will redirect it to the UI textbox
    print(message)
    sys.stdout.flush()

def backup_registry_key(key_path, value_name):
    """Backs up a specific registry key value before changing it."""
    try:
        root_key_str, sub_key_path = key_path.split('\\', 1)
        root_key = getattr(reg, root_key_str)

        with reg.OpenKey(root_key, sub_key_path, 0, reg.KEY_READ) as key:
            value, _ = reg.QueryValueEx(key, value_name)
            with open(BACKUP_FILE, "a", encoding='utf-8') as f:
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
        # Using DEVNULL for stderr to avoid clutter, but logging it in case of an error
        result = subprocess.run(
            command, shell=shell, check=True, capture_output=True, text=True, encoding='utf-8', errors='ignore',
            startupinfo=subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESHOWWINDOW, wShowWindow=subprocess.SW_HIDE)
        )
        if result.stdout:
            log_change(f"Command output: {result.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        log_change(f"[ERROR] Command '{command}' failed with exit code {e.returncode}")
        if e.stderr:
            log_change(f"Stderr: {e.stderr.strip()}")
    except Exception as e:
        log_change(f"[ERROR] Failed to run command '{command}': {e}")


# --- Spoofing & Cleaner Functions (Identical to the original script) ---
# --- All functions from spoof_disk_serials to check_registry are unchanged ---

def spoof_disk_serials():
    log_change("\n--- Starting Disk Spoofing ---")
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
    log_change("\n--- Starting GUID & BIOS Spoofing ---")
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
    log_change("\n--- Starting PC Name Spoofing ---")
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
                    continue
        log_change(f"PC Name successfully spoofed to: {new_name}")
    except Exception as e:
        log_change(f"[ERROR] PC Name spoofing failed: {e}")

def spoof_mac_address():
    log_change("\n--- Starting MAC Address Spoofing ---")
    try:
        net_class_key_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, net_class_key_path) as net_class_key:
            for i in range(reg.QueryInfoKey(net_class_key)[0]):
                try:
                    adapter_key_name = reg.EnumKey(net_class_key, i)
                    adapter_path = f"{net_class_key_path}\\{adapter_key_name}"
                    with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, adapter_path, 0, reg.KEY_WRITE) as adapter_key:
                        try:
                            driver_desc, _ = reg.QueryValueEx(adapter_key, "DriverDesc")
                            if "virtual" in driver_desc.lower() or "vpn" in driver_desc.lower():
                                continue # Skip virtual adapters
                            new_mac = generate_random_mac()
                            backup_registry_key(f"HKEY_LOCAL_MACHINE\\{adapter_path}", "NetworkAddress")
                            reg.SetValueEx(adapter_key, "NetworkAddress", 0, reg.REG_SZ, new_mac)
                            log_change(f"Spoofed MAC for '{driver_desc}' to {new_mac}")
                        except FileNotFoundError:
                            continue
                except OSError:
                    break
    except Exception as e:
        log_change(f"[ERROR] MAC spoofing failed: {e}")

def spoof_smbios():
    log_change("\n--- Starting SMBIOS Spoofing ---")
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
    log_change("\n--- Starting Product ID Spoofing ---")
    prod_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    try:
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, prod_path, 0, reg.KEY_WRITE) as key:
            new_id = f"{generate_random_string(5)}-{generate_random_string(5)}-{generate_random_string(5)}-{generate_random_string(5)}"
            backup_registry_key(f"HKEY_LOCAL_MACHINE\\{prod_path}", "ProductId")
            reg.SetValueEx(key, "ProductId", 0, reg.REG_SZ, new_id)
            log_change(f"Spoofed ProductId to {new_id}")
    except Exception as e:
        log_change(f"[ERROR] Product ID spoofing failed: {e}")

def clean_cache(name, paths):
    log_change(f"\n--- Cleaning {name} Cache ---")
    for path in paths:
        full_path = os.path.expandvars(path)
        if os.path.exists(full_path):
            try:
                if os.path.isdir(full_path):
                    shutil.rmtree(full_path, ignore_errors=True)
                else:
                    os.remove(full_path)
                log_change(f"Removed {full_path}")
            except Exception as e:
                log_change(f"[ERROR] Failed to remove {full_path}: {e}")
        else:
            log_change(f"Path not found, skipping: {full_path}")

def sechex_cleaner():
    log_change("\n--- Running Cleaner ---")
    run_command("ipconfig /flushdns")
    clean_cache("Temp Folders", ["%temp%", r"C:\Windows\Temp", r"%userprofile%\Recent"])
    run_command("netsh int ip reset")
    run_command("netsh winsock reset")
    ac_processes = ["faceit.exe", "vgc.exe", "vgtray.exe", "BattleEye.exe", "BEservice.exe"]
    for proc in ac_processes:
        run_command(f"taskkill /f /im {proc}")
    clean_ubisoft_cache()
    clean_valorant_cache()
    log_change("\nCleaner finished!")

def clean_ubisoft_cache():
    clean_cache("Ubisoft", [r"%LOCALAPPDATA%\Ubisoft Game Launcher"])

def clean_valorant_cache():
    clean_cache("Valorant/Riot", [r"%LOCALAPPDATA%\Riot Games"])

def get_system_info():
    log_change("\n--- Gathering System Information ---")
    info_commands = {
        "System Info": "systeminfo",
        "Disk Info": "wmic diskdrive get model,serialnumber",
        "MAC Address": "getmac",
        "PC Name": "hostname"
    }
    for name, cmd in info_commands.items():
        log_change(f"\n--- {name} ---")
        run_command(cmd)

def check_registry():
    log_change("\n--- Running Registry Checker ---")
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


# --- Classic GUI Application Class ---
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("errorrail's sigma spoofer!1!11")
        self.geometry("750x600")

        # Configure grid layout
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # --- Frames ---
        top_frame = ttk.Frame(self, padding="10 10 10 0")
        top_frame.grid(row=0, column=0, sticky="ew")
        top_frame.columnconfigure(0, weight=1)
        
        main_frame = ttk.Frame(self, padding="10")
        main_frame.grid(row=1, column=0, sticky="nsew")
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(0, weight=1)

        button_frame = ttk.Frame(main_frame, padding="10")
        button_frame.grid(row=0, column=0, sticky="ns")

        # --- Widgets ---
        title_font = font.Font(family="Helvetica", size=18, weight="bold")
        self.title_label = ttk.Label(top_frame, text="errorrail's sigma spoofer!!1", font=title_font)
        self.title_label.grid(row=0, column=0, sticky="w")
        
        self.status_label = ttk.Label(top_frame, text="", font=("Helvetica", 10))
        self.status_label.grid(row=0, column=1, sticky="e", padx=10)

        self.log_textbox = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, state="disabled")
        self.log_textbox.grid(row=0, column=1, sticky="nsew", padx=5)
        self.log_textbox.configure(font=("Consolas", 9))

        # --- Buttons ---
        self.buttons = {}
        button_info = [
            ("All In One", self.run_all_in_one),
            ("Spoof PC IDs", self.run_spoof_pc_ids),
            ("Spoof Hardware", self.run_spoof_hardware),
            ("Run Cleaner", self.run_cleaner),
            ("Clean Game Caches", self.run_clean_caches),
            ("System Utilities", self.run_sys_utils)
        ]
        
        for i, (text, command) in enumerate(button_info):
            style = ttk.Style()
            style.configure("TButton", padding=6, relief="flat")
            button = ttk.Button(button_frame, text=text, command=lambda cmd=command: self.start_threaded_task(cmd), width=20)
            button.grid(row=i, column=0, pady=7)
            self.buttons[text] = button

        # --- Initial Setup ---
        self.redirect_logging()
        self.initialize_app()

    def start_threaded_task(self, task_function):
        """Starts a given function in a new thread to avoid freezing the GUI."""
        for btn in self.buttons.values():
            btn.configure(state="disabled")

        thread = threading.Thread(target=self.run_task, args=(task_function,))
        thread.daemon = True
        thread.start()

    def run_task(self, task_function):
        """The wrapper for the task that re-enables buttons when done."""
        try:
            task_function()
        except Exception as e:
            log_change(f"[FATAL UI ERROR] An unexpected error occurred: {e}")
        finally:
            if is_admin():
                for btn in self.buttons.values():
                    btn.configure(state="normal")

    def redirect_logging(self):
        """Redirects print statements to the log textbox."""
        class TextboxRedirector:
            def __init__(self, textbox):
                self.textbox = textbox

            def write(self, text):
                self.textbox.configure(state="normal")
                self.textbox.insert("end", text)
                self.textbox.see("end")
                self.textbox.configure(state="disabled")

            def flush(self):
                pass
        
        sys.stdout = TextboxRedirector(self.log_textbox)

    def initialize_app(self):
        log_change("[WARNING] This program might brick/break your system! I, 'errorrail', am not responsable for damage done to your system!!")
        """Initializes backup files and checks for admin rights."""
        if not is_admin():
            self.status_label.configure(text="[FATAL] Run as Administrator!", foreground="red")
            for btn in self.buttons.values():
                btn.configure(state="disabled")
            log_change("[FATAL] Administrator privileges are required. Please re-run as admin.")
        else:
            self.status_label.configure(text="Admin privileges detected.", foreground="green")
            with open(BACKUP_FILE, "w", encoding='utf-8') as f:
                f.write("Windows Registry Editor Version 5.00\n\n")
            log_change("Script started. Logging and backups are active.")
            log_change(f"Backup file created: {BACKUP_FILE}")
            log_change(f"Log file created: {LOG_FILE}")
    
    # --- Button Command Functions (Identical to previous version) ---
    def run_all_in_one(self):
        spoof_guids_and_bios()
        spoof_pc_name()
        spoof_product_id()
        spoof_disk_serials()
        spoof_mac_address()
        spoof_smbios()
        sechex_cleaner()
        log_change("\n--- ALL IN ONE SPOOF COMPLETE ---")
        log_change("\n[IMPORTANT] A system RESTART is required for all changes to take full effect.")

    def run_spoof_pc_ids(self):
        spoof_guids_and_bios()
        spoof_pc_name()
        spoof_product_id()
        log_change("\n--- PC IDENTIFIERS SPOOFED ---")
        log_change("\n[IMPORTANT] A system RESTART is required for changes to take full effect.")

    def run_spoof_hardware(self):
        spoof_disk_serials()
        spoof_mac_address()
        spoof_smbios()
        log_change("\n--- HARDWARE SPOOFED ---")
        log_change("\n[IMPORTANT] A system RESTART is required for changes to take full effect.")

    def run_cleaner(self):
        sechex_cleaner()

    def run_clean_caches(self):
        clean_ubisoft_cache()
        clean_valorant_cache()
        log_change("\n--- Specific caches cleaned. ---")

    def run_sys_utils(self):
        get_system_info()
        check_registry()

if __name__ == "__main__":
    app = App()
    app.mainloop()