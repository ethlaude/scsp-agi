import os
import psutil
from mitreattack.stix20 import MitreAttackData

# Load the MITRE ATT&CK dataset (enterprise-attack.json file must be in the same directory)
mitre_attack_data = MitreAttackData("enterprise-attack.json")

# Retrieve techniques associated with APT38
apt38 = mitre_attack_data.get_groups_by_alias("APT38")
apt38_techniques = []
if apt38:
    apt38_data = apt38[0]
    if 'techniques' in apt38_data:
        apt38_techniques = [technique['name'] for technique in apt38_data['techniques']]

# Example list of suspicious keywords (processes related to APT38 techniques)
suspicious_keywords = [
    # Windows Processes
    "cmd.exe", "powershell.exe", "wmic.exe", "rundll32.exe", "regsvr32.exe",
    "schtasks.exe", "taskmgr.exe", "svchost.exe", "mimikatz.exe", "mshta.exe",
    "winword.exe", "excel.exe", "outlook.exe",

    # macOS Processes
    "osascript", "launchd", "cron", "curl", "wget",
    "python", "ruby", "perl", "bash", "ssh",

    # Suspicious Command Line Arguments
    "-EncodedCommand", "-ExecutionPolicy", "Invoke-WebRequest", "bypass", "hidden",
    "/C", "/K", "systeminfo", "netstat", "tasklist", "ipconfig"
]

# Check all running processes
for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
    try:
        proc_name = proc.info['name']
        proc_cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''

        # Compare process name and command line with suspicious keywords
        if any(keyword in proc_name.lower() or keyword in proc_cmdline.lower() for keyword in suspicious_keywords):
            print(f"\nSuspicious Process Found:")
            print(f"Process Name: {proc_name}")
            print(f"PID: {proc.info['pid']}")
            print(f"Command Line: {proc_cmdline}")
        
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        continue

# Display techniques associated with APT38
print("\nAPT38 Techniques Detected in ATT&CK Framework:")
for technique in apt38_techniques:
    print(f"- {technique}")