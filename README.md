# Ethical-Hacking-Projects
This is my learning journey for ethical hacking and python (pt. 1)


Each Program has it's own function:

1- arp-sniffer.py : Requires an interface input (can change in the code, at the bottom - to eth0 or other interfaces)
2- arp-spoofer.py : Requires user input of a target (-t or --target) and a spoof IP (-s or --spoof)
3- mac_changer.py : Requires user input of an interface (-i or --interface) and a new MAC address (-m or --mac)
4- network_scanner.py : Requires the user to change the scan range in the code itself
5- Code_Injector.py : Requires the user to activate IP_FORWARD in the terminal (if using on a remote target) and also use 
                      "iptables -I FORWARD -j NFQUEUE --queue-num 0" in the terminal to set a queue number (has to be 0, unless changed in code)
                      after finished use or program, use "iptables -F" in the terminal (or Wifi Connection won't work for the target)
6- dns_spoof.py : Requires the user to create an NFQUEUE in terminal and also change 2 strings in the code to redirect the target to the users specified websites
7- replace_download.py : Requires the user to create an NFQUEUE in terminal and also turn on apache2 in the users linux (start own server) or the user can just                               redirect the download of the target to another download link.
