# Imports
import subprocess, os, argparse, sys, re, getpass

# Recon.py is a script that will automate the use of recon-ng and NMAP for passive and active discovery based on a domain

def _get_arguments():
    parser = argparse.ArgumentParser()  # Define the argument parser
    parser.add_argument("domain", help="The domain to recon")   # Domain to start recon
    parser.add_argument("-o", "--output", help="The output format. Acceptable formats are: csv,excel,json", choices=["csv","excel","json"], required=True) # output choices
    parser.add_argument("-w", "--workspace", help="The name of the workspace to use for this run", required=True) # Workstpace to use for recon run
    return parser.parse_args()

def _check_install(): # Validate that recon-ng and recon-cli are installed with simple system tests for files. Fail and exit if either are not present
    reconng = False
    reconcli = False
    nmap = False
    if os.access("recon-ng", os.F_OK):
        reconng = True
    if os.access("reconcli", os_F_OK):
        reconcli = True
    if os.access("nmap", os.F_OK):
        nmap = True
    if reconng or reconcli or nmap == False:
        sys.exit("Error: recon-ng and recon-cli must be installed. Please check installation")
    return

def _check_recon_modules(): # Look for the presence of required modules. If not present use subprocess to install items not present on the list
    modules = [
        "import/nmap",
        "recon/domains-hosts/google_site_web",
        "recon/domains-hosts/shodan_hostname",
        "recon/hosts-hosts/resolve",
        "recon/hosts-ports/shodan_ip",
        "recon/netblocks-hosts/shodan_net",
        "reporting/csv",
        "reporting/json",
        "reporting/xlsx"
    ]
    modulelist = subprocess.run(["recon-cli", "-M"], capture_output=True)   # Check for required modules
    for i in modules:
        if bytes(i, "utf-8") in modulelist.stdout: # subprocess returns a bytes object, so convert string to bytes to check the output for each item
            return
        else:
            print(f"Could not find module {i}, installing now..")
            subprocess.run(["recon-cli", f"-C marketplace install {i}"])
            return

def _check_api_key():   # Checks for the presence of the Shodan API key. If not present it will prompt the user to add it using getpass (hides password from user / terminal)
    reg = re.compile(rb'shodan \| [A-Za-z}+')   # Regex to identify if shodan key is in output of command
    api_check = subprocess.run(["recon-cli", "-C keys list"], capture_output=True)
    if reg.findall(api_check.stdout):
        return  # End function and continue if they key exists
    else:
        key = getpass.getpass(prompt="API key for Shodan not found. Please enter it now: ")
        print("Adding key..")
        subprocess.run(["recon-cli", f"-C keys add shodan_api {key}"])
        return  # End function after adding shodan API key

def _run_passive(modules: list, args: list):
    for i in modules:
        try:
            subprocess.run(["recon-cli", "-w", {args.workspace}, "-m", {i}, "-o", f"SOURCE={args.domain}", "-x", ">/dev/null"])
        except:
            sys.exit("An Error Occurred")
    return
    

