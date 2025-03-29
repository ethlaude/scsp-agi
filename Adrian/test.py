import subprocess
import platform
import requests
import psutil
import re
import os
import json
import time
from typing import Dict, List, Tuple, Optional
import os

# Replace with your NVD API key (optional, but recommended to avoid rate limits)
# Get one at https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY = os.getenv('NVD_API_KEY')


# NVD API base URL
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_running_applications() -> List[Dict[str, str]]:
    """
    Get a list of running applications with their names and versions.
    Returns a list of dictionaries with 'name' and 'version' keys.
    """
    applications = []
    
    # Get process information based on the operating system
    if platform.system() == "Darwin":  # macOS
        # Get list of applications using the 'ps' command
        result = subprocess.run(
            ["ps", "-A", "-o", "comm"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        
        if result.returncode != 0:
            print("Error getting process list.")
            return []
        
        # Process each line to extract application name
        for line in result.stdout.splitlines()[1:]:  # Skip header
            app_path = line.strip()
            if not app_path or '/' not in app_path:
                continue
                
            app_name = os.path.basename(app_path)
            
            # Try to get version information
            version = get_application_version(app_name)
            
            # Only add applications with meaningful names (skip system processes)
            if app_name and not app_name.startswith('.') and app_name not in ['.com.apple','ps', 'bash', 'sh', 'zsh']:
                applications.append({
                    'name': app_name,
                    'version': version
                })
    else:  # Linux or other systems
        for proc in psutil.process_iter(['name', 'exe']):
            try:
                proc_info = proc.info
                if proc_info['exe'] and os.path.exists(proc_info['exe']):
                    app_name = os.path.basename(proc_info['exe'])
                    
                    # Try to get version information
                    version = get_application_version(app_name)
                    
                    # Only add applications with meaningful names
                    if app_name and not app_name.startswith('.') and app_name not in ['ps', 'bash', 'sh', 'zsh']:
                        applications.append({
                            'name': app_name,
                            'version': version
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    
    # Remove duplicates while preserving order
    unique_apps = []
    seen = set()
    
    for app in applications:
        app_tuple = (app['name'], app['version'])
        if app_tuple not in seen:
            seen.add(app_tuple)
            unique_apps.append(app)
    
    return unique_apps

def get_application_version(app_name: str) -> Optional[str]:
    """Attempt to get version information for an application"""
    try:
        # Try using --version flag (common in many applications)
        result = subprocess.run(
            [app_name, "--version"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True,
            timeout=2
        )
        
        if result.returncode == 0:
            # Look for version patterns in the output
            version_output = result.stdout or result.stderr
            version_match = re.search(r'version\s+(\d+(\.\d+)+)', version_output, re.IGNORECASE)
            if version_match:
                return version_match.group(1)
            
            # Try another common pattern
            version_match = re.search(r'(\d+\.\d+(\.\d+)*)', version_output)
            if version_match:
                return version_match.group(1)
    except (subprocess.SubprocessError, FileNotFoundError, PermissionError):
        pass
    
    return None

def search_nvd_for_cves(app_name: str, app_version: Optional[str] = None) -> List[Dict]:
    """
    Search NVD for CVEs related to the application.
    
    Args:
        app_name: Name of the application
        app_version: Version of the application (optional)
        
    Returns:
        List of CVE information dictionaries
    """
    try:
        # Build query parameters
        params = {
            "keywordSearch": app_name,
            "resultsPerPage": 20
        }
        
        # Add API key if provided
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        
        # Make the request to NVD API
        response = requests.get(NVD_API_BASE_URL, params=params, headers=headers)
        
        # Check for rate limiting
        if response.status_code == 403:
            print("Rate limit exceeded. Consider getting an API key from NIST.")
            # Simple backoff
            time.sleep(6)
            # Try once more
            response = requests.get(NVD_API_BASE_URL, params=params, headers=headers)
        
        if response.status_code != 200:
            print(f"Error from NVD API: {response.status_code} - {response.text}")
            return []
        
        # Parse the response
        data = response.json()
        
        # Extract CVEs from results
        cves = []
        for vuln in data.get("vulnerabilities", []):
            cve_item = vuln.get("cve", {})
            cve_id = cve_item.get("id")
            
            # Extract description
            descriptions = cve_item.get("descriptions", [])
            description = next((desc.get("value") for desc in descriptions if desc.get("lang") == "en"), "No description available")
            
            # Extract metrics (CVSS score)
            metrics = cve_item.get("metrics", {})
            cvssv3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if "cvssMetricV31" in metrics else {}
            cvssv2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}) if "cvssMetricV2" in metrics else {}
            
            # Use CVSS v3 if available, otherwise fallback to v2
            cvss_score = cvssv3.get("baseScore", cvssv2.get("baseScore"))
            
            # Check if this CVE applies to the specific version
            # We need to check configurations for CPE matches
            configurations = cve_item.get("configurations", [])
            
            # If version is provided, check if this CVE applies to the specific version
            version_matched = True
            if app_version and configurations:
                version_matched = False
                for config in configurations:
                    for node in config.get("nodes", []):
                        for cpe_match in node.get("cpeMatch", []):
                            # Check if CPE criteria includes our software
                            cpe = cpe_match.get("criteria", "")
                            if app_name.lower() in cpe.lower():
                                # CPE format: cpe:2.3:a:vendor:product:version
                                # If versionStartIncluding/versionEndExcluding are present, use them
                                if "versionStartIncluding" in cpe_match and "versionEndExcluding" in cpe_match:
                                    try:
                                        # Basic version comparison (not perfect for all version schemes)
                                        if (cpe_match["versionStartIncluding"] <= app_version < 
                                            cpe_match["versionEndExcluding"]):
                                            version_matched = True
                                            break
                                    except:
                                        # If comparison fails, be conservative and include it
                                        version_matched = True
                                        break
                                else:
                                    # If no version range specified, include it
                                    version_matched = True
                                    break
            
            # Only include if no version filtering needed or version matches
            if version_matched:
                cves.append({
                    'cve_id': cve_id,
                    'cvss': cvss_score,
                    'summary': description
                })
        
        return cves
    
    except Exception as e:
        print(f"Error searching NVD: {e}")
        return []

def main():
    print("Scanning for running applications...")
    
    # Check if API credentials are set
    if NVD_API_KEY == "":
        print("WARNING: You are using the NVD API without an API key. This may lead to rate limiting.")
        print("Get your API key at https://nvd.nist.gov/developers/request-an-api-key")
    
    # Get running applications
    applications = get_running_applications()
    
    if not applications:
        print("No applications detected.")
        return
    
    print(f"Found {len(applications)} applications running.")
    print("\nSearching for vulnerabilities...")
    
    # Track all found CVEs
    all_cves = {}
    
    # For each application, search for CVEs
    for app in applications:
        print(f"\nChecking {app['name']}" + (f" (version {app['version']})" if app['version'] else ""))
        
        cves = search_nvd_for_cves(app['name'], app['version'])
        
        if cves:
            print(f"  Found {len(cves)} potential vulnerabilities:")
            for cve in cves:
                cve_id = cve['cve_id']
                if cve_id not in all_cves:
                    all_cves[cve_id] = {
                        'affected_apps': [app['name']],
                        'cvss': cve['cvss'],
                        'summary': cve['summary']
                    }
                else:
                    all_cves[cve_id]['affected_apps'].append(app['name'])
                
                print(f"    - {cve_id} (CVSS: {cve['cvss']})")
                print(f"      {cve['summary'][:100]}..." if len(cve['summary']) > 100 else f"      {cve['summary']}")
        else:
            print("  No known vulnerabilities found.")
    
    # Summary report
    print("\n===== VULNERABILITY SUMMARY =====")
    if all_cves:
        print(f"Found {len(all_cves)} unique CVEs affecting your applications:\n")
        
        # Sort CVEs by CVSS score (highest first)
        sorted_cves = sorted(all_cves.items(), key=lambda x: x[1]['cvss'] if x[1]['cvss'] else 0, reverse=True)
        
        for cve_id, cve_data in sorted_cves:
            print(f"CVE: {cve_id}")
            print(f"CVSS Score: {cve_data['cvss']}")
            print(f"Affected Applications: {', '.join(cve_data['affected_apps'])}")
            print(f"Summary: {cve_data['summary']}")
            print("-" * 50)
    else:
        print("No CVEs found for your running applications.")
    
    print("\nNote: This is not a comprehensive security assessment. Some vulnerabilities may not be detected.")
    print("For a more thorough analysis, consider using dedicated security scanning tools.")

if __name__ == "__main__":
    main()