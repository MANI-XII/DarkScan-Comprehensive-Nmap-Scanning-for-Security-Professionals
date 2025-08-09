#!/usr/bin/python
# -- coding: utf-8 --
#===============================
#  By : 1ucif3r
#  Github.com/1ucif3r
#  instagram.com/0x1ucif3r
#  twitter.com/0x1ucif3r
#
#  www.dark4rmy.com
#================================
import sys
import os
import time
import signal
from time import sleep
from sys import argv
from platform import system

defaultportscan = "50"

def clear_screen():
    """Clear the terminal screen for Windows and Linux/macOS."""
    os.system("cls" if os.name == "nt" else "clear")

def darkmenu():
    print("\n \033[1;91m your output file is in your current directory \033[1;m")
    os.system("pwd" if os.name != "nt" else "cd")
    print(" \033[1;91m Your current directory \033[1;m")
    print("\n \033[1;91m1-) Back to Main Menu \n 2-) Exit \033[1;m")
    choicedonus = input("root""\033[1;91m@DarkScan:~$\033[1;m ")
    if choicedonus == "1":
        clear_screen()
        darkscan()
    elif choicedonus == "2":
        clear_screen()
        print(" \033[1;91m@Good Bye !! Happy Hacking !!\033[1;m")
        sys.exit()
    else:
        print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
        time.sleep(2)
        darkscan()

def sigint_handler(signum, frame):
    clear_screen()
    print("CTRL+C detected!")
    print(" \033[1;91mGood Bye !! Happy Hacking !!\033[1;m")
    sys.exit()

signal.signal(signal.SIGINT, sigint_handler)

clear_screen()

def logo():
    print("""\033[1;91m

██████╗  █████╗ ██████╗ ██╗  ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗    
██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║    
██║  ██║███████║██████╔╝█████╔╝     ███████╗██║     ███████║██╔██╗ ██║    
██║  ██║██╔══██║██╔══██╗██╔═██╗     ╚════██║██║     ██╔══██║██║╚██╗██║    
██████╔╝██║  ██║██║  ██║██║  ██╗    ███████║╚██████╗██║  ██║██║ ╚████║    
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  v1  
                                                                          
             ||  By : KanyaRashi || 
\033[1;m """)

def menu():
    logo()
    print("""
        1-) Normal Scanning
        2-) Firewall Bypass
        3-) Vulnerability Scanning
        u-) Update
        00-) Contact
        0-) Exit
        """)

def darkscan():
    menu()
    choice = input("root""\033[1;91m@DarkScan:~$\033[1;m ")
    clear_screen()
    if choice == "1":
        dscan()
    elif choice == "2":
        firewall()
    elif choice == "3":
        vul()
    elif choice == "u":
        update()
    elif choice == "00":
        credit()
    elif choice == "0":
        exit_program()
    elif choice == "":
        menu()
    else:
        print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
        time.sleep(2)
        darkscan()

def dscan():
    clear_screen()
    logo()
    print("""
        1-) Default Scan
        2-) Host Discovery
        3-) Port(SYN) Scan
        4-) Port(TCP) Scan
        5-) Port(UDP) Scan
        6-) Null scan (-sN)
        7-) FIN scan (-sF)
        8-) OS Analysis and Version Discovery
        9-) Nmap Script Engineering (default)
        00-) Back to Menu
        """)
    choicedscan = input("root""\033[1;91m@DScan:~$\033[1;m ")
    clear_screen()
    if choicedscan == "1":
        ds()
    elif choicedscan == "2":
        hd()
    elif choicedscan == '3':
        synscan()
    elif choicedscan == "4":
        tcpscan()
    elif choicedscan == "5":
        udpscan()
    elif choicedscan == "6":
        nullscan()
    elif choicedscan == "7":
        finscan()
    elif choicedscan == "8":
        oavd()
    elif choicedscan == "9":
        nse()
    elif choicedscan == "00":
        darkscan()

def firewall():
    clear_screen()
    logo()
    print("""
        1-) Script Bypass (--script=firewall-bypass)
        2-) Data Length (--data-length <number> )
        3-) Smash (-ff)
        00-) Back to Menu
        """)
    choicefirewall = input("root""\033[1;91m@FirewallBypass:~$\033[1;m ")
    clear_screen()
    if choicefirewall == "1":
        sb()
    elif choicefirewall == "2":
        dl()
    elif choicefirewall == '3':
        smash()
    elif choicefirewall == "00":
        darkscan()

def vul():
    clear_screen()
    logo()
    print("""
        1-) Default Vuln Scan (--script vuln)
        2-) FTP Vuln Scan
        3-) SMB Vuln Scan
        4-) HTTP Vuln Scan
        5-) SQL Injection Vuln Scan
        6-) Stored XSS Vuln Scan
        7-) Dom Based XSS vuln Scan
        00-) Back to Menu
        """)
    choicevul = input("root""\033[1;91m@VulnerabilityScanning:~$\033[1;m ")
    clear_screen()
    if choicevul == "1":
        dvs()
    elif choicevul == "2":
        ftpvulscan()
    elif choicevul == '3':
        smbvulscan()
    elif choicevul == "4":
        httpvulscan()
    elif choicevul == "5":
        sqlvulscan()
    elif choicevul == "6":
        storedxssscan()
    elif choicevul == "7":
        domxssscan()
    elif choicevul == "00":
        darkscan()

def update():
    print("This Tool is Only Available for Linux and Similar Systems.")
    choiceupdate = input("Continue Y / N: ")
    if choiceupdate.lower() in ['y', 'yes']:
        os.system("git clone https://github.com/D4RK-4RMY/Darkscan.git")
        os.system("cd Darkscan")
        os.system("python3 darkscan.py")

def ds():
    print("Starting Default Scan...")
    time.sleep(1)
    clear_screen()
    logo()
    birhedef = input("Enter Your Target (IP address or domain): ")
    if not birhedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport1 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport1:
            topport1 = defaultportscan
        output_file = f"{birhedef}-output.txt"
        try:
            os.system(f"nmap -vv --top-ports={topport1} {birhedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def hd():
    print("Starting Host Discovery...")
    time.sleep(1)
    clear_screen()
    logo()
    ikihedef = input("Enter Your Target (IP address or domain): ")
    if not ikihedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport2 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport2:
            topport2 = defaultportscan
        output_file = f"HostD-{ikihedef}-output.txt"
        try:
            os.system(f"nmap -vv -Pn --top-ports={topport2} {ikihedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def synscan():
    print("Starting Port(SYN) Scan...")
    time.sleep(1)
    clear_screen()
    logo()
    uchedef = input("Enter Your Target (IP address or domain): ")
    if not uchedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport3 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport3:
            topport3 = defaultportscan
        output_file = f"{uchedef}-SYN-output.txt"
        try:
            os.system(f"nmap -vv -sS --top-ports={topport3} {uchedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def tcpscan():
    print("Starting Port(TCP) Scan...")
    time.sleep(1)
    clear_screen()
    logo()
    dorthedef = input("Enter Your Target (IP address or domain): ")
    if not dorthedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport4 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport4:
            topport4 = defaultportscan
        output_file = f"{dorthedef}-TCP-output.txt"
        try:
            os.system(f"nmap -vv -sT --top-ports={topport4} {dorthedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def udpscan():
    print("Starting Port(UDP) Scan...")
    time.sleep(1)
    clear_screen()
    logo()
    beshedef = input("Enter Your Target (IP address or domain): ")
    if not beshedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport5 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport5:
            topport5 = defaultportscan
        output_file = f"{beshedef}-UDP-output.txt"
        try:
            os.system(f"nmap -vv -sU --top-ports={topport5} {beshedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def nullscan():
    print("Starting Null Scan (-sN)...")
    time.sleep(1)
    clear_screen()
    logo()
    altihedef = input("Enter Your Target (IP address or domain): ")
    if not altihedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport6 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport6:
            topport6 = defaultportscan
        output_file = f"{altihedef}-NULL-output.txt"
        try:
            os.system(f"nmap -vv -sN --top-ports={topport6} {altihedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def finscan():
    print("Starting FIN Scan (-sF)...")
    time.sleep(1)
    clear_screen()
    logo()
    yedihedef = input("Enter Your Target (IP address or domain): ")
    if not yedihedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport7 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport7:
            topport7 = defaultportscan
        output_file = f"{yedihedef}-FIN-output.txt"
        try:
            os.system(f"nmap -vv -sF --top-ports={topport7} {yedihedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def oavd():
    print("Starting OS Analysis and Version Discovery...")
    time.sleep(1)
    clear_screen()
    logo()
    sekizhedef = input("Enter Your Target (IP address or domain): ")
    if not sekizhedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport8 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport8:
            topport8 = defaultportscan
        output_file = f"{sekizhedef}-OSVD-output.txt"
        try:
            os.system(f"nmap -vv -sS -sV -O --top-ports={topport8} {sekizhedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def nse():
    print("Starting Nmap Script Engineering...")
    time.sleep(1)
    clear_screen()
    logo()
    dokuzhedef = input("Enter Your Target (IP address or domain): ")
    if not dokuzhedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport9 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport9:
            topport9 = defaultportscan
        output_file = f"{dokuzhedef}-NSE-output.txt"
        try:
            os.system(f"nmap -vv --script=default --top-ports={topport9} {dokuzhedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def sb():
    print("Starting Nmap Scripting Firewall Bypass...")
    time.sleep(1)
    clear_screen()
    logo()
    onhedef = input("Enter Your Target (IP address or domain): ")
    if not onhedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport10 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport10:
            topport10 = defaultportscan
        output_file = f"{onhedef}-FirewallBypass-output.txt"
        try:
            os.system(f"nmap -vv --script=firewall-bypass --top-ports={topport10} {onhedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def dl():
    print("Starting Data Length Scan...")
    time.sleep(1)
    clear_screen()
    logo()
    onbirhedef = input("Enter Your Target (IP address or domain): ")
    if not onbirhedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport11 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport11:
            topport11 = defaultportscan
        datalength = input("Data Length (number): ")
        output_file = f"{onbirhedef}-DataLength-output.txt"
        try:
            os.system(f"nmap --data-string {datalength} --top-ports={topport11} {onbirhedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def smash():
    print("Starting Smash (-ff) Scan...")
    time.sleep(1)
    clear_screen()
    logo()
    onikihedef = input("Enter Your Target (IP address or domain): ")
    if not onikihedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport12 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport12:
            topport12 = defaultportscan
        output_file = f"{onikihedef}-Smash-output.txt"
        try:
            os.system(f"nmap -vv -ff --top-ports={topport12} {onikihedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def dvs():
    print("Starting Default Vulnerability Scan...")
    time.sleep(1)
    clear_screen()
    logo()
    onuchedef = input("Enter Your Target (IP address or domain): ")
    if not onuchedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport13 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport13:
            topport13 = defaultportscan
        output_file = f"{onuchedef}-VulnScan-output.txt"
        try:
            os.system(f"nmap -vv -sV -ff -Pn --top-ports={topport13} --script vuln {onuchedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def ftpvulscan():
    print("Starting FTP Vulnerability Scan...")
    time.sleep(1)
    clear_screen()
    logo()
    ondorthedef = input("Enter Your Target (IP address or domain): ")
    if not ondorthedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport14 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport14:
            topport14 = defaultportscan
        output_file = f"{ondorthedef}-FTPVulnScan-output.txt"
        try:
            os.system(f"nmap -vv -sV -ff -Pn --top-ports={topport14} --script ftp* {ondorthedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def smbvulscan():
    print("Starting SMB Vulnerability Scan...")
    time.sleep(1)
    clear_screen()
    logo()
    onbeshedef = input("Enter Your Target (IP address or domain): ")
    if not onbeshedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport15 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport15:
            topport15 = defaultportscan
        output_file = f"{onbeshedef}-SMBVulnScan-output.txt"
        try:
            os.system(f"nmap -vv -sV -ff -Pn --top-ports={topport15} --script smb* {onbeshedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def httpvulscan():
    print("Starting HTTP Vulnerability Scan...")
    time.sleep(1)
    clear_screen()
    logo()
    onaltihedef = input("Enter Your Target (IP address or domain): ")
    if not onaltihedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport16 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport16:
            topport16 = defaultportscan
        output_file = f"{onaltihedef}-HTTPVulnScan-output.txt"
        try:
            os.system(f"nmap -vv -sV -ff -Pn --top-ports={topport16} --script http* {onaltihedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def sqlvulscan():
    print("Starting SQL Injection Vulnerability Scan...")
    time.sleep(1)
    clear_screen()
    logo()
    onyedihedef = input("Enter Your Target (IP address or domain): ")
    if not onyedihedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport17 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport17:
            topport17 = defaultportscan
        output_file = f"{onyedihedef}-SQLVulnScan-output.txt"
        try:
            os.system(f"nmap -vv -sV -ff -Pn --top-ports={topport17} --script http-sql-injection {onyedihedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def storedxssscan():
    print("Starting Stored XSS Vulnerability Scan...")
    time.sleep(1)
    clear_screen()
    logo()
    onsekizhedef = input("Enter Your Target (IP address or domain): ")
    if not onsekizhedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport18 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport18:
            topport18 = defaultportscan
        output_file = f"{onsekizhedef}-StoredXSSScan-output.txt"
        try:
            os.system(f"nmap -vv -sV -ff -Pn --top-ports={topport18} --script http-stored-xss {onsekizhedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def domxssscan():
    print("Starting DOM Based XSS Vulnerability Scan...")
    time.sleep(1)
    clear_screen()
    logo()
    ondokuzhedef = input("Enter Your Target (IP address or domain): ")
    if not ondokuzhedef:
        print("Please Enter Target")
        print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
        time.sleep(2)
        clear_screen()
        darkscan()
    else:
        topport19 = input("Top Port? Example: 10 or 50, Default 50: ")
        if not topport19:
            topport19 = defaultportscan
        output_file = f"{ondokuzhedef}-DOMXSSScan-output.txt"
        try:
            os.system(f"nmap -vv -sV -ff -Pn --top-ports={topport19} --script http-dombased-xss {ondokuzhedef} -oN {output_file}")
            print(f"Scan completed. Results saved to {output_file}")
        except Exception as e:
            print(f"An error occurred: {e}")
    darkmenu()

def credit():
    print("""\033[1;91m
                 ▄▄·        ▐ ▄ ▄▄▄▄▄ ▄▄▄·  ▄▄· ▄▄▄▄▄    
                ▐█ ▌▪▪     •█▌▐█•██  ▐█ ▀█ ▐█ ▌▪•██      
                ██ ▄▄ ▄█▀▄ ▐█▐▐▌ ▐█.▪▄█▀▀█ ██ ▄▄ ▐█.▪    
                ▐███▌▐█▌.▐▌██▐█▌ ▐█▌·▐█ ▪▐▌▐███▌ ▐█▌·    
                ·▀▀▀  ▀█▄▀▪▀▀ █▪ ▀▀▀  ▀  ▀ ·▀▀▀  ▀▀▀  
                ===================================== 
          NOTE : For Back To Menu Press 1 OR For Exit Press 2
       ==========================================================                                                                   
\033[1;m """)
    print("""                 manikantaedulapuram@gmail.com
    """)
    choice = input("root""\033[1;91m@Credit:~$\033[1;m ")
    if choice == "1":
        clear_screen()
        darkscan()
    elif choice == "2":
        clear_screen()
        print(" \033[1;91mGood Bye !! Happy Hacking !!\033[1;m")
        sys.exit()
    else:
        print("Invalid option! Redirecting to main menu...")
        time.sleep(2)
        darkscan()

def exit_program():
    print(" \033[1;91mGood Bye !! Happy Hacking !!\033[1;m")
    sys.exit()

if __name__ == "__main__":
    darkscan()