#!/usr/bin/env python

import subprocess


subprocess.call("cd /root/Desktop/openvpn", shell=True)

choice = input("Enter 1 for THM. \nEnter 2 for HTB.\nEnter 3 for VHL. \nEnter 4 for Kill")
choice = int(choice)

if choice == 1:
    print("You chose Try Hack ME")
    subprocess.call("openvpn undefinedshinobi.ovpn", shell=True)

elif choice == 2:
    print("You chose Hack The Box")
    subprocess.call("openvpn Shinobibugh.ovpn", shell=True)

elif choice == 3:
    print("You chose Virtual Hacking Labs")
    subprocess.call("openvpn ", shell=True)



elif choice == 4:
    print("You chose to Kill OpenVPN")
    subprocess.call("killall openvpn", shell=True)

else:
    print("Invalid choice")

