#!/usr/bin/python3
"""
Usage:
  executor.py -h | --help
  executor.py bruteforce (--rhosts=<rhosts>) ( --ssh | --rdp | --vsphereapi) [--user=<user>]

Options:
  --rhosts=<rhosts>     File containing IPv4 targets one per line ie gathered from a masscan
  --user=<user>         Supply the user vs defaults for ssh or rdp, vsphere will use default users
  --ssh                 Attempt brute force of ssh
  --rdp                 Attempt brute force of rdp
  --vsphereapi          Attempt brute force of vsphere api
"""
import os
import sys
import ssl
import json
import time
import sqlite3
import logging
import ipaddress
import subprocess
import concurrent.futures

from getpass import getpas
from datetime import datetime

try:
    import nmap
    import paramiko
    from docopt import docopt
    from pyVmomi import vim
    from pyVim.connect import SmartConnect
except ImportError as ex:
    logging.info("Make sure to: pip3 install -r requirements.txt")
    logging.info(str(ex))


class Users:
    """
    Create an object for our default users
    """
    def __init__(self):
        self.esxi_user = "root"
        self.vc_user = "administrator@vsphere.local"
        self.rdp_user = "administrator"
        self.ssh_user = "root"

class db_queries:
    """
    Create an object for our database creation queries
    """
    def __init__(self, table: str='YOUR_TABLE'):
        self.create_table = """CREATE TABLE {} (id integer PRIMARY KEY,ip text NOT NULL,username text NOT NULL,password text NOT NULL)""".format(table)
        self.list_tables = """SELECT name FROM sqlite_master WHERE type='table'"""
        self.list_rows = """SELECT id, ip, username, password FROM {}""".format(table)
        self.add_row = """INSERT INTO {} (id, ip, username, password) VALUES (?,?,?,?)""".format(table)
        self.count_rows = """SELECT Count(*) FROM {}""".format(table)

def password_prompt():
    """
    Logic to ask and validate password prior to code execution.
    This is to ensure you do not waste time brute forcing if you have the wrong password.
    """
    while True:
        password1 = getpass("Enter password for login attempts: ")
        password2 = getpass("Retype password to confirm: ")

        if password1 == password2:
            logging.info("Password match continuing with: {}".format(password1))
            return password1
        else:
            logging.info("Password mismatch try again please, or ctrl+c to exit")
            pass

def validate_ipv4(ip: str) -> bool:
    """
    Validate an IPv4 address.
    """
    logging.info("Entering validate_IPv4: {}".format(ip))
    try:
        ipaddress.ip_network(ip)
        logging.info("IPv4 valid: {}".format(ip))
        return True
    except Exception as ex:
        logging.info("[-] Subnet validation failed: {}".format(ip))
        return False

def is_program_install(program: str) -> bool:
    """
    Check if program is installed
    """
    try:
        logging.info("Verifying that {} exists".format(program))
        subprocess.call([program])
        return True
    except OSError as ex:
        logging.info("Exiting: please install {} to continue.".format(program))
        sys.exit(1)

def create_file(file_name: str, username: str, password: str, protocol: str, data: list) -> str:
    """
    Create a file from a list of given data.
    """
    logging.info("Entering create_file: {}".format(file_name))
    with open(file_name, "w+") as file:
        file.write("Username: {}\n".format(username))
        file.write("Password: {}\n".format(password))
        file.write("Protocol: {}\n".format(protocol))
        file.write("Target Count: {}\n".format(len(data)))
        for item in data:
            file.write("{}\n".format(item))
    return file_name

def generate_list_from_file(data_file):
    """Convert rhosts file to list"""
    logging.info("Entering generate_list_from_file: {}".format(data_file))
    data_list = []
    with open(data_file, 'r') as my_file:
        for line in my_file:
            ip = line.strip('\n').strip(' ')
            if validate_ipv4(ip):
                data_list.append(ip)
    return set(data_list)

def create_new_sqlite3_db():
    """
    Create our sqlite3 db if not present in working directory.
    """
    working_dir = os.path.dirname(os.path.abspath(__file__))
    logging.info("Checking for existing sqlite3 database in working directory")
    if os.path.isfile(working_dir + "/db.sqlite3"):
        logging.info("sqlite3 database found exiting database setup")
        logging.info("Checking database structure")
        logging.debug("Checking for ssh_asset table")        
        con = connect_db()
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ssh_assets';")

def connect_db(path: str='db.sqlite3') -> object:
    """
    Connect to our sqlite3 db.
    """
    return sqlite3.connect('db.sqlite3')

def execute_sql(connection: object, query: str) -> list:
    """
    Execute SQL against connection
    """
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchall()

def nmap_for_vsphere_version(targets_file: str) -> dict:
    """
    Nmap scan a list of targets on port 443 for the vmware-version.

    Args:
        targets_file:   A file with each target on a new line

    Returns:
        Dictionary containing a list of vcenter servers and a list of esxi servers
    """
    logging.info("Entering nmap_for_vsphere_version with file: {}".format(targets_file))
    try:
        logging.info("Setting up nmap scanner")
        my_scanner = nmap.PortScanner()
    except nmap.nmap.PortScannerError as ex:
        logging.info("NMAP is not installed to OS path exiting: {}".format(str(ex)))
        os._exit(1)
    
    # python nmap does not take a file for the hosts parameter, you can trick it with setting hosts to an ip and adding -iL
    # nmap switches
    #   -n: no dns
    #   -Pn: no ping
    #   --disable-arp-ping: disable default arping for systems on same layer2
    full_results = my_scanner.scan(hosts='192.168.0.1', arguments='-n -Pn -p443 --open --script vmware-version -iL {}'.format(targets_file))
    scan_results = full_results['scan']
    vcenter_servers = []
    esxi_servers = []
    for host in my_scanner.all_hosts():
        try:
            if 'Server version' in scan_results[host]['tcp'][443]['script']['vmware-version']:
                host_results = scan_results[host]['tcp'][443]['script']['vmware-version'].split("\n")
                v = [s for s in host_results if "Server" in s]
                if "vCenter" in v[0]:
                    vcenter_servers.append(host)
                elif "ESXi" in v[0]:
                    esxi_servers.append(host)
        except Exception as ex:
            logging.info("Could not find vsphere version for: {}".format(host))
    return {"vcenter": vcenter_servers, "esxi": esxi_servers}

def login_rdp(target, username, password, port: int=3389, timeout: int=5) -> dict:
    """
    Single rdp login attempt.

    Requires:
        xfreerdp
    """
    cmd = ['xfreerdp','-u', '{}'.format(username),'-p',  '{}'.format(password),'--ignore-certificate','--authonly','{}:{}'.format(target, int(port))]
    logging.info("[#] Login attempt: RDP : {} : {} : {}".format(username, password, target))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # out, err = map(B, proc.communicate())
    out, err = proc.communicate()
    if proc.returncode == 0:
        logging.info("[+] Login success: RDP : {} : {} : {}".format(username, password, target))
        return {"Target": target, "Login": True}
    else:
        logging.info("[-] Login failed: RDP : {} : {} : {}".format(username, password, target)) 
        return {"Target": target, "Login": False}

def login_ssh(target, username, password, port: int=22, timeout: int=5) -> dict:
    """
    Single SSH login attempt.
    """
    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy)
        logging.info("[#] Login attempt: SSH : {} : {} : {}".format(username, password, target))
        client.connect(
            hostname=target, 
            port=port, 
            username=username, 
            password=password, 
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            )
        client.close()
        logging.info("[+] Login success: SSH : {} : {} : {}".format(username, password, target))
        return {"Target": target, "Login": True}
    except Exception:
        logging.info("[-] Login failed: SSH : {} : {} : {}".format(username, password, target)) 
        return {"Target": target, "Login": False}

def login_vsphere(target, username, password) -> dict:
    """
    Single vSphere API login attempt.
    """
    try:
        s = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        s.verify_mode = ssl.CERT_NONE
        logging.info("[#] Login attempt: vSphereAPI : {} : {} : {}".format(username, password, target))
        si = SmartConnect(
            host=target,
            user=username,
            pwd=password,
            sslContext=s
            )
        logging.info("[+] Login success: vSphereAPI : {} : {} : {}".format(username, password, target))
        return {"Target": target, "Login": True}
    except Exception as ex:
        logging.info("[-] Login failed: vSphereAPI : {} : {} : {}".format(username, password, target)) 
        return {"Target": target, "Login": False}

def login_concurrent(protocol: str, targets: list, username: str, password: str):
    """
    Enumerate a vSphere Server to find virtual machines and details.

    Args:
        vsphere: a list of target IPs
        vsphere_user: a user
        vsphere_passwords: a list of passwords to use for login
        wanted: a list of IP address to look for in the returned inventory

    Returns:
        A list of dictionaries containing the results from a single vSphere server
    """
    logging.info("Entering login_concurrent for protocol: {}".format(protocol))
    results_list = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=50) as pool:
        if protocol.lower() == "ssh":
            results = {pool.submit(login_ssh, target, username, password): target for target in targets}
        elif protocol.lower() == "vsphereapi":
            results = {pool.submit(login_vsphere, target, username, password): target for target in targets}
        elif protocol.lower() == "rdp":
            results = {pool.submit(login_rdp, target, username, password): target for target in targets}
        else:
            logging.debug("Error in login_concurrent check protocol selection logic")
            sys.exit(1)
        for future in concurrent.futures.as_completed(results):
            if future.result():
                results_list.append(future.result())
    return results_list

def sort_results_dict(data: list) -> list:
    """
    Sort the results dictionary into a failed and success list
    """
    success_list = []
    failure_list = []
    for d in data:
        if d['Login'] is True:
            success_list.append(d['Target'])
        elif d['Login'] is False:
            failure_list.append(d['Target'])
    return success_list, failure_list

def main():
    """
    Run the code
    """
    opts = docopt(__doc__)

    TIME = datetime.now().strftime('%m-%d-%Y_%H:%M')

    LOG_NAME = "{}_executor_runtime.log".format(TIME)
    WORKING_DIR = os.path.dirname(os.path.abspath(__file__)) + "/{}".format(LOG_NAME)
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=logging.DEBUG,
        handlers=[
            logging.FileHandler(filename=WORKING_DIR, mode="w+"),
            logging.StreamHandler()
            ]
        )

    logging.info("Parameters passed: {}".format(opts))

    password = password_prompt()

    users = Users()

    # Establish user based on arg or default for ssh and rdp only
    # This helps with test cases but for the most part we care about the root and administrator local account
    if opts['--user']:
        username = opts['--user']
    elif opts['--ssh']:
        username = users.ssh_user
    elif opts['--rdp']:
        username = users.rdp_user

    rhosts_file = opts['--rhosts']

    targets_list = generate_list_from_file(rhosts_file)

    if opts['--ssh']:
        ssh_results = login_concurrent(
            protocol="ssh",
            targets=targets_list,
            username=username,
            password=password
        )
        ssh_success_list, ssh_failure_list = sort_results_dict(ssh_results)
        if ssh_success_list:
            ssh_results_file_succeed = "{}_executor_results_ssh_succeeded.txt".format(TIME)
            create_file(
                file_name=ssh_results_file_succeed,
                username=username,
                password=password,
                protocol="ssh",
                data=ssh_success_list
            )
        if ssh_failure_list:
            ssh_results_file_failed = "{}_executor_results_ssh_failed.txt".format(TIME)
            create_file(
                file_name=ssh_results_file_failed,
                username=username,
                password=password,
                protocol="ssh",
                data=ssh_failure_list
            )
    elif opts['--rdp']:
        is_program_install("xfreerdp")
        rdp_results = login_concurrent(
            protocol="rdp",
            targets=targets_list,
            username=username,
            password=password
        )
        rdp_success_list, rdp_failure_list = sort_results_dict(rdp_results)
        if rdp_success_list:
            rdp_results_file_succeed = "{}_executor_results_rdp_succeeded.txt".format(TIME)
            create_file(
                file_name=rdp_results_file_succeed,
                username=username,
                password=password,
                protocol="rdp",
                data=rdp_success_list
            )
        if rdp_failure_list:
            rdp_results_file_failed = "{}_executor_results_rdp_failed.txt".format(TIME)
            create_file(
                file_name=rdp_results_file_failed,
                username=username,
                password=password,
                protocol="rdp",
                data=rdp_failure_list
            )
    elif opts['--vsphereapi']:
        nmap_results = nmap_for_vsphere_version(rhosts_file)

        esxi_results = login_concurrent(
            protocol="vsphereapi",
            targets=nmap_results['esxi'],
            username=users.esxi_user,
            password=password
        )
        esxi_success_list, esxi_failure_list = sort_results_dict(esxi_results)
        if esxi_success_list:
            esxi_results_file_succeed = "{}_executor_results_esxi_succeeded.txt".format(TIME)
            create_file(
                file_name=esxi_results_file_succeed,
                username=users.esxi_user,
                password=password,
                protocol="vsphereAPI",
                data=esxi_success_list
            )
        if esxi_failure_list:
            esxi_results_file_failed = "{}_executor_results_esxi_failed.txt".format(TIME)
            create_file(
                file_name=esxi_results_file_failed,
                username=users.esxi_user,
                password=password,
                protocol="vsphereAPI",
                data=esxi_failure_list
            )

        vc_results = login_concurrent(
            protocol="vsphereAPI",
            targets=nmap_results['vcenter'],
            username=users.vc_user,
            password=password
        )
        vc_success_list, vc_failure_list = sort_results_dict(vc_results)
        if vc_success_list:
            vc_results_file_succeed = "{}_executor_results_esxi_succeeded.txt".format(TIME)
            create_file(
                file_name=vc_results_file_succeed,
                username=users.vc_user,
                password=password,
                protocol="vsphereAPI",
                data=vc_success_list
            )
        if vc_failure_list:
            vc_results_file_failed = "{}_executor_results_esxi_failed.txt".format(TIME)
            create_file(
                file_name=vc_results_file_failed,
                username=users.vc_user,
                password=password,
                protocol="vsphereAPI",
                data=vc_failure_list
            )
    logging.info("Run Complete")

if __name__ == '__main__':
    main()

