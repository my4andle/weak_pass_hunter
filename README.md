# weak_pass_hunter
Designed to test a single password against a single protocol

# masscan first
I highly recommend masscanning for the desired port and then running this tool against those results.  

# Protocol support
RDP  
SSH  
vSphereAPI  

# Usage
"""  
Usage:   
  executor.py -h | --help  
  executor.py bruteforce (--rhosts=\<rhosts\>) ( --ssh | --rdp | --vsphereapi) [--user=\<user\>]  

Options:  
  --rhosts=\<rhosts\>   File containing IPv4 targets one per line ie gathered from a masscan  
  --user=\<user\>       Supply the user vs defaults for ssh or rdp, vsphere will use default users  
  --ssh                 Attempt brute force of ssh  
  --rdp                 Attempt brute force of rdp  
  --vsphereapi          Attempt brute force of vsphere api  
"""  

# Output
Logfiles are generated for both successful and failed logins.

# Warning
I am not responsible for the usage of this tool.  This is provided to assist teams in securing their infrastructure by finding weak credentials.  
