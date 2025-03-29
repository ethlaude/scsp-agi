import os
import psutil
import json
import requests
import time
import subprocess
import re

# Set the CPU usage threshold to trigger detection (15% to reduce false positives)
cpu_threshold = 15

# Path to the high-risk processes file
script_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.dirname(script_dir)

# Try multiple possible locations for high_risk_processes.json
possible_paths = [
    os.path.join(script_dir, "high_risk_processes.json"),
    os.path.join(base_dir, "scsp-agi", "high_risk_processes.json"),
    "scsp-agi/high_risk_processes.json"
]

# Try to find the file in any of the possible locations
high_risk_file_path = None
for path in possible_paths:
    if os.path.exists(path):
        high_risk_file_path = path
        print(f"✅ Found high-risk processes file at: {high_risk_file_path}")
        break

# Load high-risk processes from the JSON file
try:
    if high_risk_file_path:
        with open(high_risk_file_path, "r") as file:
            data = json.load(file)
            high_risk_processes = data.get("high_risk_processes", [])
        print(f"✅ Successfully loaded {len(high_risk_processes)} high-risk processes")
    else:
        raise FileNotFoundError("Could not find high_risk_processes.json")
except (FileNotFoundError, json.JSONDecodeError) as e:
    print(f"WARNING: {e}")
    print("Using default high-risk process list")
    high_risk_processes = [
        "svchost.exe", "cmd.exe", "powershell.exe", "wmic.exe", "rundll32.exe", 
        "mimikatz.exe", "osascript", "bash", "python", "ruby", "perl", 
        "ssh", "curl", "wget", "netcat", "nc", "ftp", "chrome", "firefox", 
        "chatgpt", "openai"
    ]

def query_gemma(prompt):
    """
    Send a prompt to Ollama API using the Gemma model
    """
    try:
        url = "http://localhost:11434/api/generate"
        payload = {
            "model": "gemma3",
            "prompt": prompt,
            "temperature": 0.1,
            "stream": False
        }
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 200:
            return response.json()["response"]
        else:
            return None
    except requests.exceptions.ConnectionError:
        return None
    except Exception as e:
        return None

def analyze_with_gemma(process_info):
    """
    Analyzes a process using Gemma 3 AI
    """
    prompt = f"""
    Analyze this process and determine if it is suspicious:
    - Name: {process_info['name']}
    - PID: {process_info['pid']}
    - Command Line: {process_info['cmdline']}
    - CPU Usage: {process_info['cpu_usage']}%
    - Memory Usage: {process_info['memory_percent']}%
    """
    return query_gemma(prompt)

def get_detailed_process_info(proc):
    try:
        p = psutil.Process(proc.info['pid'])
        return {
            'name': proc.info['name'].lower() if proc.info['name'] else '',
            'pid': proc.info['pid'],
            'cmdline': ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else '',
            'cpu_usage': p.cpu_percent(interval=0.1),
            'memory_percent': p.memory_percent()
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def save_results_to_file(results):
    with open("results.txt", "w") as file:
        file.write("Detected High-CPU Processes:\n")
        for result in results:
            file.write(f"\nProcess Name: {result['name']}\n")
            file.write(f"PID: {result['pid']}\n")
            file.write(f"CPU Usage: {result['cpu_usage']}%\n")
            file.write(f"Memory Usage: {result['memory_percent']}%\n")
            file.write(f"Command Line: {result['cmdline']}\n")
            file.write("-" * 60 + "\n")
    print("✅ Results saved to results.txt for comparison with btop.")

def run_top_comparison():
    try:
        print("🔄 Running top for cross-checking...")
        # Use macOS top command to capture a single sample of processes
        result = subprocess.run(["top", "-l", "1", "-stats", "pid,command,cpu"], 
                             capture_output=True, text=True, check=True)
        
        # Save the output to a file
        with open("top_output.txt", "w") as f:
            f.write(result.stdout)
            
        print("✅ top output saved to top_output.txt")
    except subprocess.CalledProcessError:
        print("❌ Error running top command.")
    except FileNotFoundError:
        print("❌ top not found. This is unusual for macOS.")

def compare_with_top():
    try:
        with open("top_output.txt", "r") as top_file, open("results.txt", "r") as results_file:
            top_data = top_file.readlines()
            results_data = results_file.readlines()

            print("\n🔍 Cross-checking detected processes with top output:")
            for line in results_data:
                if "Process Name:" in line:
                    process_name = line.split(":")[1].strip()
                    matched = False
                    for top_line in top_data:
                        if process_name in top_line:
                            # Parse CPU usage if available in the line
                            cpu_match = re.search(r'\b(\d+\.\d+)\b', top_line)
                            cpu_info = f" - CPU: {cpu_match.group(1)}%" if cpu_match else ""
                            
                            print(f"✅ Matched in top: {process_name}{cpu_info}")
                            print(f"   {top_line.strip()}")
                            matched = True
                            break
                    
                    if not matched:
                        print(f"❓ Not found in top output: {process_name}")
    except FileNotFoundError:
        print("❌ Comparison files not found. Run the script first to generate results.")

print(f"🚀 Starting high-CPU process check (Threshold: {cpu_threshold}%)...")

high_cpu_processes = []
for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
    try:
        proc_info = get_detailed_process_info(proc)
        if proc_info and proc_info['cpu_usage'] > cpu_threshold:
            # Check if this is a high-risk process
            is_high_risk = any(name in proc_info['name'] for name in high_risk_processes)
            
            # Format the output differently based on risk level
            if is_high_risk:
                print(f"\n⚠️ High-CPU Suspicious Process Detected: {proc_info['name']} (PID: {proc_info['pid']}) - CPU: {proc_info['cpu_usage']:.1f}%")
                ai_analysis = analyze_with_gemma(proc_info)
                if ai_analysis:
                    print("🤖 AI Analysis (Gemma 3):")
                    print(ai_analysis)
            else:
                print(f"\nℹ️ High-CPU Process (Not Suspicious): {proc_info['name']} (PID: {proc_info['pid']}) - CPU: {proc_info['cpu_usage']:.1f}%")
            
            # Add to the list regardless of risk level
            high_cpu_processes.append(proc_info)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        continue

if high_cpu_processes:
    save_results_to_file(high_cpu_processes)
    run_top_comparison()
    compare_with_top()
else:
    print("✅ No suspicious high-CPU processes detected.")
