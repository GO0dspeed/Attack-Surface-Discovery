# Imports
import subprocess, os, argparse, sys, re, getpass

# Recon.py is a script that will automate the use of recon-ng and NMAP for passive and active discovery based on a domain

def _get_arguments():
    parser = argparse.ArgumentParser()  # Define the argument parser
    subparsers = parser.add_subparsers(help="sub-command help", dest="command") # Define subparser
    parser.add_argument("-o", "--output", help="The output format. Acceptable formats are: csv,xlsx,json", choices=["csv","xlsx","json"], required=True) # output choices
    parser.add_argument("-w", "--workspace", help="The name of the workspace to use for this run", required=True) # Workstpace to use for recon run
    parser.add_argument("-f", "--filename", help="Name or path of output file", required=True)  # output file
    domain_parser = subparsers.add_parser("domain", help="The domain to recon")   # Domain subparser
    domain_parser.add_argument("input", help="The domain to recon")
    ip_parser = subparsers.add_parser("ip", help="Text file containing a list of IPs (one per line)")   # IP File subparser
    ip_parser.add_argument("input", help="The filename containing a list of IPs to recon")
    nmap_parser = subparsers.add_parser("nmap", help="Import NMAP results (xml) to create target list")   # NMAP file subparser
    nmap_parser.add_argument("input", help="The xml output filename from NMAP to parse")
    return parser.parse_args()

def _check_install(): # Validate that recon-ng, recon-cli, eyewitness, and nmap are installed with simple system tests for files. Fail and exit if either are not present
    reconng = False
    reconcli = False
    nmap = False
    eyewitness = False
    for i in os.path.expandvars("$PATH").split(":"):
        if os.access(f"{i}/recon-ng", os.F_OK):
            reconng = True
        elif os.access(f"{i}/recon-cli", os.F_OK):
            reconcli = True
        elif os.access(f"{i}/nmap", os.F_OK):
            nmap = True
        elif os.access(f"{i}/Eyewitness.py", os.F_OK):
            eyewitness = True
    if (reconng or reconcli or nmap) == False:
        sys.exit("Error: recon-ng and recon-cli must be installed. Please check installation")
    return

def _check_recon_modules(): # Look for the presence of required modules. If not present use subprocess to install items not present on the list
    modules = [
        "import/nmap",
        "import/list",
        "recon/domains-hosts/hackertarget",
        "recon/domains-hosts/google_site_web",
        "recon/domains-hosts/shodan_hostname",
        "recon/hosts-hosts/resolve",
        "recon/hosts-ports/shodan_ip",
        "recon/netblocks-hosts/shodan_net",
        "discovery/info_disclosure/interesting_files",
        "recon/hosts-hosts/reverse_resolve",
        "reporting/csv",
        "reporting/json",
        "reporting/xlsx"
    ]
    modulelist = subprocess.run(["recon-cli", "-M"], capture_output=True)   # Check for required modules
    for i in modules:
        if bytes(i, "utf-8") in modulelist.stdout: # subprocess returns a bytes object, so convert string to bytes to check the output for each item
            continue
        else:
            print(f"Could not find module {i}, installing now..")
            subprocess.run(["recon-cli", f"-C marketplace install {i}"])
            continue

def _check_api_key():   # Checks for the presence of the Shodan API key. If not present it will prompt the user to add it using getpass (hides password from user / terminal)
    reg = re.compile(rb'shodan_api \| [A-Za-z]+')   # Regex to identify if shodan key is in output of command
    api_check = subprocess.run(["recon-cli", "-C keys list"], capture_output=True)
    if reg.findall(api_check.stdout):
        return  # End function and continue if they key exists
    else:
        key = getpass.getpass(prompt="API key for Shodan not found. Please enter it now: ")
        print("Adding key..")
        subprocess.run(["recon-cli", f"-C keys add shodan_api {key}"])
        return  # End function after adding shodan API key

def _run_passive(modules: list, args: dict):    # Runs passive recon for a given domain. Using the list of recon modules above
    for i in modules:
        try:
            if args.command == "domain":
                subprocess.run(["recon-cli", "-w", args.workspace, "-m", i, "-o", f"SOURCE={args.input}", "-x"], stdout=subprocess.DEVNULL) # Run passive enumeration. Output is supressed. DB will update with results
            else:
                subprocess.run(["recon-cli", "-w", args.workspace, "-m", i, "-x"], stdout=subprocess.DEVNULL) # Run passive enumeration. Output is supressed. DB will update with results
        except Exception as e:
            sys.exit(f"An Error Occurred during passive recon. Please refer to error message:\n{e}")   # end program
    return

def _get_ip_addresses(args: dict):    # attempt to get IP addresses from recon-cli database and parse them in to a list. Write to a file for active enumeration later
    try:
        db_output = subprocess.run(["recon-cli", "-w", args.workspace, "-C", "db query select ip_address from hosts", ], capture_output=True)
        regex = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')   # snag only the IP address from the output
        ip_list = regex.findall(db_output.stdout.decode("utf-8"))
        with open("/tmp/ip-list.txt", "w") as fh:
            fh.write("\n".join(ip_list) + "\n")
    except Exception as e:
        sys.exit(f"An error occurred gathering IP addresses: Please see below:\n{e}")   # quit the program if any errors occur and inform the user

def _run_nmap(): # Run active recon on the target IPs found during passive recon
    try:
        subprocess.run(["nmap", "-sC", "-sV", "-oX", "/tmp/nmap-out", "-iL", "/tmp/ip-list.txt"], stdout=subprocess.DEVNULL)
    except Exception as e:
        sys.exit(f"An error occured during active recon. Please refer to error message:\n{e}")

def _run_eyewitness(args): # Run Eyewitness active recon on the target
    try:
        subprocess.run(["EyeWitness.py", "--web", "-f", "/tmp/ip-list.txt", "--resolve" ,"--prepend-https", "-d", f"{args.output}"], stdout=subprocess.DEVNULL)
    except Exception as e:
        sys.exit(f"An error occurred during execution of eyewitness. Please refer to error message:\n{e}")

def _import_nmap_results(args: dict): # import nmap XML file to recon-ng for completeness
    try:
        subprocess.run(["recon-cli", "-w", f"{args.workspace}", "-m", "import/nmap", "-o", f"FILENAME={args.input}" if args.command == "nmap" else "FILENAME=/tmp/nmap-out", "-x"], stdout=subprocess.DEVNULL)
    except Exception as e:
        _cleanup_temp_files()
        sys.exit(f"An error occurred importing the NMAP results. Please refer to error message:\n{e}") # fail out of program if an error occurs

def _import_file_ips(args: dict):
    try:
        subprocess.run(["recon-cli", "-w", args.workspace, "-m", "import/list", "-o", "COLUMN=ip_address", "-o", "TABLE=hosts", "-o", f"FILENAME={args.input}", "-x"], stdout=subprocess.DEVNULL)
    except Exception as e:
        sys.exit(f"An error occurred importing {args.input}. Please refer to the error message:\n{e}")

def _write_output_results(args: list):  # output results to specified file format
    try:
        subprocess.run(["recon-cli", "-w", args.workspace, "-m", f"reporting/{args.output}", "-o", f"FILENAME={args.filename}", "-o", "HEADERS=true", "-o", "TABLE=ports", "-x"], stdout=subprocess.DEVNULL) # report out adding header row and using ports table to list services
    except Exception as e:
        sys.exit(f"An error occurred writing results. Please refer to error message:\n{e}")

def _cleanup_temp_files():  # housekeeping post run
    try:
        print("Cleaning up temporary files", flush=True)
        os.remove("/tmp/ip-list.txt")
        os.remove("/tmp/nmap-out")
    except Exception:
        print(f"Unable to remove files in /tmp/. Please delete /tmp/ip-list.txt and /tmp/nmap-out manually..")  # just in case the files are not deleted automatically

def main():
    args = _get_arguments()
    recon_modules = [
        "recon/hosts-hosts/resolve",
        "recon/hosts-hosts/reverse_resolve",
        "recon/hosts-ports/shodan_ip",
        "recon/domains-hosts/google_site_web",
        "recon/domains-hosts/hackertarget",
        "recon/domains-hosts/shodan_hostname",
        "recon/hosts-hosts/resolve",
        "recon/hosts-hosts/reverse_resolve",
        "recon/hosts-ports/shodan_ip",
        "recon/netblocks-hosts/shodan_net",
        "discovery/info_disclosure/interesting_files"
    ]

    print(f"[*] Attempting automatic passive and active recon on {args.input}.\nThis could take some time for larger domains or address ranges...", flush=True)
    print(f"[*] Beginning installation pre-checks..", flush=True)
    _check_install()
    _check_recon_modules()
    _check_api_key()
    print(f"[*] Pre-checks passed. Beginning passive recon on {args.input}. This can take some time...", flush=True)
    if args.command == "nmap":
        _import_nmap_results(args)
    elif args.command == "ip":
        _import_file_ips(args)
    _run_passive(recon_modules, args)
    _get_ip_addresses(args)
    print(f"[*] Passive recon completed. Beginning active recon. Be sure you have permission to scan these IP addresses...", flush=True)
    _run_nmap()
    _run_eyewitness(args)
    print(f"[*] Active recon completed on {args.input}.", flush=True)
    print(f"[*] Normalizing results and outputting to {args.output}.")
    _import_nmap_results(args)
    _write_output_results(args)
    print(f"[*] Results written to {args.filename}.", flush=True)
    print(f"[*] Cleaning up temporary files")
    _cleanup_temp_files

if __name__ == "__main__":
    main()
