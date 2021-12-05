# Imports
import subprocess, os, argparse, sys, re, getpass

# Recon.py is a script that will automate the use of recon-ng and NMAP for passive and active discovery based on a domain

def _get_arguments():
    parser = argparse.ArgumentParser()  # Define the argument parser
    parser.add_argument("domain", help="The domain to recon")   # Domain to start recon
    parser.add_argument("-o", "--output", help="The output format. Acceptable formats are: csv,excel,json", choices=["csv","excel","json"], required=True) # output choices
    parser.add_argument("-w", "--workspace", help="The name of the workspace to use for this run", required=True) # Workstpace to use for recon run
    parser.add_argument("-f", "--filename", help="Name or path of output file", required=True)  # output file
    return parser.parse_args()

def _check_install(): # Validate that recon-ng, recon-cli, and nmap are installed with simple system tests for files. Fail and exit if either are not present
    reconng = False
    reconcli = False
    nmap = False
    for i in os.path.expandvars("$PATH").split(":"):
        if os.access(f"{i}/recon-ng", os.F_OK):
            reconng = True
        elif os.access(f"{i}/recon-cli", os.F_OK):
            reconcli = True
        elif os.access(f"{i}/nmap", os.F_OK):
            nmap = True
    if (reconng or reconcli or nmap) == False:
        sys.exit("Error: recon-ng and recon-cli must be installed. Please check installation")
    return

def _check_recon_modules(): # Look for the presence of required modules. If not present use subprocess to install items not present on the list
    modules = [
        "import/nmap",
        "recon/domains-hosts/hackertarget",
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
    reg = re.compile(rb'shodan_api \| [A-Za-z]+')   # Regex to identify if shodan key is in output of command
    api_check = subprocess.run(["recon-cli", "-C keys list"], capture_output=True)
    if reg.findall(api_check.stdout):
        return  # End function and continue if they key exists
    else:
        key = getpass.getpass(prompt="API key for Shodan not found. Please enter it now: ")
        print("Adding key..")
        subprocess.run(["recon-cli", f"-C keys add shodan_api {key}"])
        return  # End function after adding shodan API key

def _run_passive(modules: list, args: list):    # Runs passive recon for a given domain. Using the list of recon modules above
    for i in modules:
        try:
            subprocess.run(["recon-cli", "-w", args.workspace, "-m", i, "-o", f"SOURCE={args.domain}", "-x"]) # Run passive enumeration. Output is supressed. DB will update with results
        except Exception as e:
            sys.exit(f"An Error Occurred during passive recon. Please refer to error message:\n{e}")   # end program
    return

def _get_ip_addresses(args: list):    # attempt to get IP addresses from recon-cli database and parse them in to a list. Write to a file for active enumeration later
    try:
        db_output = subprocess.run(["recon-cli", "-w", args.workspace, "-C", "db query select ip_address from hosts", ], capture_output=True)
        regex = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')   # snag only the IP address from the output
        ip_list = regex.findall(db_output.stdout.decode("utf-8"))
        with open("/tmp/ip-list.txt", "w") as fh:
            fh.write("\n".join(ip_list) + "\n")
    except Exception as e:
        sys.exit(f"An error occurred gathering IP addresses: Please see below:\n{e}")   # quit the program if any errors occur and inform the user

def _run_active(): # Run active recon on the target IPs found during passive recon
    try:
        subprocess.run(["nmap", "-sC", "-sV", "-oX", "/tmp/nmap-out", "-iL", "/tmp/ip-list.txt"])
    except Exception as e:
        sys.exit(f"An error occured during active recon. Please refer to error message:\n{e}")

def _import_nmap_results(args: list): # import nmap XML file to recon-ng for completeness
    try:
        subprocess.run(["recon-cli", "-w", f"{args.workspace}", "-m", "import/nmap", "-o", "FILENAME=/tmp/nmap-out.xml", "-x"])
    except Exception as e:
        _cleanup_temp_files()
        sys.exit(f"An error occurred importing the NMAP results. Please refer to error message:\n{e}") # fail out of program if an error occurs

def _write_output_results(args: list):  # output results to specified file format
    try:
        subprocess.run(["recon-cli", "-w", args.workspace, "-m", f"reporting/{args.output}", "-o", f"FILENAME={args.filename}"])
    except Exception as e:
        sys.exit(f"An error occurred writing results. Please refer to error message:\n{e}")

def _cleanup_temp_files():  # housekeeping post run
    try:
        print("Cleaning up temporary files", flush=True)
        os.remove("/tmp/ip-list.txt")
        os.remove("/tmp/nmap-out.xml")
    except Exception:
        print(f"Unable to remove files in /tmp/. Please delete /tmp/ip-list.txt and /tmp/nmap-out.xml manually..")  # just in case the files are not deleted automatically

def main():
    args = _get_arguments()
    recon_modules = [
        "recon/domains-hosts/google_site_web",
        "recon/domains-hosts/hackertarget",
        "recon/domains-hosts/shodan_hostname",
        "recon/hosts-hosts/resolve",
        "recon/hosts-ports/shodan_ip",
        "recon/netblocks-hosts/shodan_net",
    ]
    print(f"Attempting automatic passive and active recon on {args.domain}.\nThis could take some time for larger domains...", flush=True)
    print(f"Beginning installation pre-checks..", flush=True)
    _check_install()
    _check_recon_modules()
    _check_api_key()
    print(f"Pre-checks passed. Beginning passive recon on {args.domain}. This can take some time...", flush=True)
    _run_passive(recon_modules, args)
    _get_ip_addresses(args)
    print(f"Passive recon completed. Beginning active recon. Be sure you have permission to scan these IP addresses...", flush=True)
    _run_active()
    print(f"Active recon completed on {args.domain}.", flush=True)
    print(f"Normalizing results and outputting to {args.output}.")
    _import_nmap_results(args)
    _write_output_results(args)
    print(f"Results written to {args.filename}.", flush=True)
    print(f"Cleaning up temporary files")
    _cleanup_temp_files

if __name__ == "__main__":
    main()
