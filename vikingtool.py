#!/usr/bin/python3
import os
import sys
import platform
import subprocess
import socket
import hashlib
import getpass
import time as sleepy
import threading

import urllib
from urllib import request

from requests import get
from colorama import Fore, Back, Style
from colorama import init, init

init(autoreset=True)
passwordlist = []


class UI:
    def __init__(self):
        pass

    @staticmethod
    def divider():
        print("-" * 80)

    @staticmethod
    def clear():
        os.system("cls") if os.name == "nt" else os.system("clear")

    @staticmethod
    def write(x, speed):
        line = x

        for s in line:
            sys.stdout.write(s)
            sys.stdout.flush()
            sleepy.sleep(speed)
        print("\n")

    def title(self, title):
        ui.clear()
        ui.divider()
        print(f"            {title}")
        ui.divider()

    def footer(self, comment):
        ui.divider()
        print(f"  {comment}")
        ui.divider()


class Spinner:
    busy = False
    delay = 0.1

    @staticmethod
    def spinning_cursor():
        while 1:
            for cursor in '|/-\\':
                yield cursor

    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay):
            self.delay = delay

    def spinner_task(self):
        while self.busy:
            sys.stdout.write(next(self.spinner_generator))
            sys.stdout.flush()
            sleepy.sleep(self.delay)
            sys.stdout.write('\b')
            sys.stdout.flush()

    def __enter__(self):
        self.busy = True
        threading.Thread(target=self.spinner_task).start()

    def __exit__(self, exception, value, tb):
        self.busy = False
        sleepy.sleep(self.delay)
        if exception is not None:
            return False


class Tools:
    def __init__(self):
        pass

    def login(self):
        ui.clear()
        allow = False
        while not allow:
            ui.clear()
            password = "3E2573A75821576A00DAE928F8A77E35EF60E176"
            guess = getpass.getpass("Please enter your password: ")
            passwordHash = hashlib.sha1(guess.encode('utf-8')).hexdigest()
            if passwordHash.lower() == password.lower():
                ui.clear()
                ui.write("Welcome Back, Viking.", 0.01)
                sleepy.sleep(2)
                return
            else:
                ui.clear()
                ui.write("Incorrect.", 0.01)
                sleepy.sleep(2)

    def depcheck(self, library):
        ui.clear()
        ui.write(f"Checking for dependencies... ({library})", 0.01)
        os.system(f'pip install {library}')
        with Spinner():
            sleepy.sleep(5)

    def splashScreen(self):
        ui.clear()
        print(" _______ .______       ___________    ____      __       ___     __     _______.")
        print("|   ____||   _  \\     |   ____\\   \\  /   /     |  |     /   \\   (_ )   /       |")
        print("|  |__   |  |_)  |    |  |__   \\   \\/   /      |  |    /  ^  \\   |/   |   (----`  ")
        print("|   __|  |      /     |   __|   \\_    _/ .--.  |  |   /  /_\\  \\        \\   \\      ")
        print("|  |     |  |\\  \\----.|  |____    |  |   |  `--'  |  /  _____  \\   .----)   |     ")
        print("|__|     | _| `._____||_______|   |__|    \\______/  /__/     \\__\\  |_______/")
        print("    ____    ____  _______ .__   __.   _______  _______     ___      .__   __.   ______  _______")
        print("    \\   \\  /   / |   ____||  \\ |  |  /  _____||   ____|   /   \\     |  \\ |  |  /      ||   ____|")
        print("     \\   \\/   /  |  |__   |   \\|  | |  |  __  |  |__     /  ^  \\    |   \\|  | |  ,----'|  |__")
        print("      \\      /   |   __|  |  . `  | |  | |_ | |   __|   /  /_\\  \\   |  . `  | |  |     |   __|")
        print("       \\    /    |  |____ |  |\\   | |  |__| | |  |____ /  _____  \\  |  |\\   | |  `----.|  |____")
        print("        \\__/     |_______||__| \\__|  \\______| |_______/__/     \\__\\ |__| \\__|  \\______||_______|")
        sleepy.sleep(5)


class LocalMachine:
    def __init__(self):

        self.ip = self.check_ip()
        #self.ip = "--Redacted--"
        self.hostname = socket.gethostname()
        self.username = getpass.getuser()
        self.os = platform.system()
        self.osDetails = platform.platform()
        self.processor = platform.processor()
        self.localip = self.get_localip()

        menulist = ["1. System Info", "\n\n0. Main Menu"]
        active = True

        while active:
            ui.title("Local Machine Menu")
            for i in menulist:
                print(i)
            ui.divider()
            choice = input("\nSelect an option: ")

            if choice == '1':
                self.display_info()
            elif choice == "0":
                active = False

    def display_info(self):
        ui.title("System Info")
        print(f"Computer Name: 		{self.hostname}")
        print(f"Username:    		{self.username}")
        print(f"\nProcessor:		{self.processor}")
        print(f"Operating system: 	{self.os}")
        print(f"OS Details:         	{self.osDetails}")
        print(f"\nPublic IP: 		{self.ip}")
        print(f"Local IP:               {self.localip}")
        ui.divider()
        input("\n\nPress enter to return to menu.")

    @staticmethod
    def get_localip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = (s.getsockname()[0])
        s.close()
        return ip

    @staticmethod
    def check_ip():
        try:
            answer = get('https://api.ipify.org').text
        except:
            answer = "Error: unable to reach https://api.ipify.org"
        return answer


class Network:
    def __init__(self):

        self.ip = self.check_ip()
        self.hostname = socket.gethostname()
        self.username = getpass.getuser()
        self.os = platform.system()
        self.osDetails = platform.platform()
        self.processor = platform.processor()
        self.localip = self.get_localip()

        active = True
        menulist = ["1. Crack Password (md5, sha1, sha224, sha256, sha384 or sha512)", "2. Brute Force Password (sha1)",
                    "\n3. Network Discovery", "\n\n0. Main Menu"]

        while active:
            ui.title("Network Menu")
            for i in menulist:
                print(i)
            ui.divider()
            choice = input("\nSelect an option: ")

            if choice == '1':
                ui.clear()

                print(
                    "##########################################################################")
                print("NOTICE:", 0.1)
                print(
                    " If you get an error while running the password cracker, it's because")
                print(" utf-8 for some reason will not read the word 'permainan'.")
                print()
                print(
                    " The issue is with the encoding of the word in the file, not the code. ")
                print(
                    " Find it within the text file, and remove that line manually, then save")
                print(
                    " You CAN delete the word, an type it in again yourself, that solves it, too")
                print(" It's on line 601,937.")
                print()
                print(
                    " Sadly I can not remove it for you, the 1's and 0's just won't allow it.")
                print(
                    "####################################################--Viking-Tool--#######")
                input("\nPress enter to continue.")
                ui.clear()
                hashpass = input("Enter your hashed password: ")

                if len(hashpass) == 32:
                    self.crackermd5(hashpass)
                elif len(hashpass) == 40:
                    self.crackersha1(hashpass)
                elif len(hashpass) == 56:
                    self.crackersha224(hashpass)
                elif len(hashpass) == 64:
                    self.crackersha256(hashpass)
                elif len(hashpass) == 96:
                    self.crackersha384(hashpass)
                elif len(hashpass) == 128:
                    self.crackersha512(hashpass)
                else:
                    print("\nI Do not recognize that hash type.")

                    input("\n\nPress enter to return.")

            elif choice == '2':
                self.brutesha1()

            elif choice == '3':
                self.networkscan()

            elif choice == '0':
                ui.clear()
                active = False

    @staticmethod
    def get_localip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = (s.getsockname()[0])
        s.close()
        return ip

    @staticmethod
    def check_ip():
        try:
            answer = get('https://api.ipify.org').text
        except:
            answer = "Error: unable to reach https://api.ipify.org"
        return answer

    def crackermd5(self, x):
        # MD5 Password Cracker (32 character long)
        ui.clear()
        flag = 0
        pass_hash = x
        wordlist = 'passwords.txt'

        try:
            pass_file = open(wordlist, "r")
        except:
            print("No password file found :(")
            sleepy.sleep(2)
            return

        print("Starting.")

        for word in pass_file:

            enc_wrd = word.encode('utf-8')
            digest = hashlib.md5(enc_wrd.strip()).hexdigest()
            try:
                ui.clear()
                print('Trying:' + word.rstrip())
                print(digest)
                print()
            except:
                pass

            if digest.strip() == pass_hash.strip():
                ui.clear()
                print("Password is: " + word)
                print("MD5: " + str(pass_hash))
                flag = 1
                break

        if flag == 0:
            print("password not found.")

        input("\n\nPress enter to return.")
        return

    def crackersha1(self, x):
        # SHA1 Password Cracker (40 chars long)
        ui.clear()
        flag = 0
        pass_hash = x
        wordlist = 'passwords.txt'

        try:
            pass_file = open(wordlist, "r")
        except:
            print("No password file found :(")
            sleepy.sleep(2)
            return

        print("Starting.")

        for word in pass_file:

            enc_wrd = word.encode('utf-8')
            digest = hashlib.sha1(enc_wrd.strip()).hexdigest()
            try:
                ui.clear()
                print('Trying:' + word.rstrip())
                print(digest)
                print()
            except:
                pass

            if digest.strip() == pass_hash.lower().strip():
                ui.clear()
                print("Password is: " + word)
                print("SHA1: " + str(pass_hash))
                flag = 1
                break

        if flag == 0:
            print("password not found.")

        input("\n\nPress enter to return.")
        return

    def crackersha224(self, x):
        # SHA224 Password Cracker (56 characters long)
        ui.clear()
        flag = 0
        pass_hash = x
        wordlist = 'passwords.txt'

        try:
            pass_file = open(wordlist, "r")
        except:
            print("No password file found :(")
            sleepy.sleep(2)
            return

        print("Starting.")

        for word in pass_file:

            enc_wrd = word.encode('utf-8')
            digest = hashlib.sha224(enc_wrd.strip()).hexdigest()
            try:
                ui.clear()
                print('Trying:' + word.rstrip())
                print(digest)
                print()
            except:
                pass

            if digest.strip() == pass_hash.lower().strip():
                ui.clear()
                print("Password is: " + word)
                print("SHA224: " + str(pass_hash))
                flag = 1
                break

        if flag == 0:
            print("password not found.")

        input("\n\nPress enter to return.")
        return

    def crackersha256(self, x):
        # SHA256 Password Cracker (64 long)
        ui.clear()
        flag = 0
        pass_hash = x
        wordlist = 'passwords.txt'

        try:
            pass_file = open(wordlist, "r")
        except:
            print("No  password file found :(")
            sleepy.sleep(2)
            return

        print("Starting.")

        for word in pass_file:

            enc_wrd = word.encode('utf-8')
            digest = hashlib.sha256(enc_wrd.strip()).hexdigest()
            try:
                ui.clear()
                print('Trying:' + word.rstrip())
                print(digest)
                print()
            except:
                pass

            if digest.strip() == pass_hash.lower().strip():
                ui.clear()
                print("Password is: " + word)
                print("SHA256: " + str(pass_hash))
                flag = 1
                break

        if flag == 0:
            print("password not found.")

        input("\n\nPress enter to return.")
        return

    def crackersha384(self, x):
        # SHA384 Password Cracker (96 characters long)
        ui.clear()
        flag = 0
        pass_hash = x
        wordlist = 'passwords.txt'

        try:
            pass_file = open(wordlist, "r")
        except:
            print("No password file found :(")
            sleepy.sleep(2)
            return

        print("Starting.", 0.05)

        for word in pass_file:

            enc_wrd = word.encode('utf-8')
            digest = hashlib.sha384(enc_wrd.strip()).hexdigest()
            try:
                ui.clear()
                print('Trying:' + word.rstrip())
                print(digest)
                print()
            except:
                pass

            if digest.strip() == pass_hash.lower().strip():
                ui.clear()
                print("Password is: " + word)
                print("SHA384: " + str(pass_hash))
                flag = 1
                break

        if flag == 0:
            print("password not found.")

        input("\n\nPress enter to return.")
        return

    def crackersha512(self, x):
        # SHA512 Password Cracker (128 characters long)
        ui.clear()
        flag = 0
        pass_hash = x
        wordlist = 'passwords.txt'

        try:
            pass_file = open(wordlist, "r")
        except:
            print("No passwowrd file found :(")
            sleepy.sleep(2)
            return

        print("Starting.")

        for word in pass_file:

            enc_wrd = word.encode('utf-8')
            digest = hashlib.sha512(enc_wrd.strip()).hexdigest()
            try:
                ui.clear()
                print('Trying:' + word.rstrip())
                print(digest)
                print()
            except:
                pass

            if digest.strip() == pass_hash.lower().strip():
                ui.clear()
                print("Password is: " + word)
                print("SHA512: " + str(pass_hash))
                flag = 1
                break

        if flag == 0:
            print("password not found.")

        input("\n\nPress enter to return.")
        return

    def brutesha1(self):
        # Brute Force SHA1 (Takes a LONG time)
        timeOld = sleepy.time()
        startTime = sleepy.time()
        timeNow = sleepy.time()

        pws = 0
        pwscounter = 0
        password = ''
        passwordHash = ''
        guess = ''
        answer = ''
        error = False
        cracked = False
        loops = 0

        chars = '1234567890abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZZ'
        charslen = len(chars)

        i, i2, i3, i4, i5, i6, i7, i8, i9, i10 = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

        c, c2, c3, c4, c5, c6, c7, c8, c9, c10 = '', '', '', '', '', '', '', '', '', ''

        ui.clear()
        passwordHash = input("Please enter the SHA-1 hash you wish to crack: ")
        print('starting...')
        startTime = sleepy.time()
        while not cracked:
            while i <= charslen - 1:
                while i2 <= charslen - 1:
                    while i3 <= charslen - 1:
                        while i4 <= charslen - 1:
                            while i5 <= charslen - 1:
                                while i6 <= charslen - 1:
                                    while i7 <= charslen - 1:
                                        while i8 <= charslen - 1:
                                            while i9 <= charslen - 1:
                                                while i10 <= charslen - 1:
                                                    timeNow = sleepy.time()
                                                    if timeNow - timeOld >= 1:
                                                        pws = pwscounter
                                                        pwscounter = 0
                                                        timeOld = sleepy.time()
                                                    c10 = chars[i10]
                                                    guess = c
                                                    guess += c2
                                                    guess += c3
                                                    guess += c4
                                                    guess += c5
                                                    guess += c6
                                                    guess += c7
                                                    guess += c8
                                                    guess += c9
                                                    guess += c10
                                                    loops += 1
                                                    hashed = hashlib.sha1(
                                                        guess.encode('utf-8')).hexdigest()
                                                    if hashed == passwordHash:
                                                        cracked = True
                                                        break
                                                    if loops >= charslen ** 10:
                                                        cracked = True
                                                        error = True
                                                        break
                                                    pwscounter += 1
                                                    i10 += 1
                                                c9 = chars[i9]
                                                i9 += 1
                                                i10 = 0
                                                if cracked:
                                                    break
                                            c8 = chars[i8]
                                            i8 += 1
                                            i9 = 0
                                            if cracked:
                                                break
                                        c7 = chars[i7]
                                        i7 += 1
                                        i8 = 0
                                        ui.clear()
                                        ui.divider()
                                        print(
                                            "                SHA1 Cracking in progress")
                                        ui.divider()
                                        print("Cracking: ", passwordHash)
                                        print("Trying:   ", hashed)
                                        print("Password: ", guess)
                                        print("pw/s:     ", pws)
                                        print("guesses:  ", loops)
                                        if cracked:
                                            break
                                    c6 = chars[i6]
                                    i6 += 1
                                    i7 = 0
                                    if cracked:
                                        break
                                c5 = chars[i5]
                                i5 += 1
                                i6 = 0
                                if cracked:
                                    break
                            c4 = chars[i4]
                            i4 += 1
                            i5 = 0
                            if cracked:
                                break
                        c3 = chars[i3]
                        i3 += 1
                        i4 = 0
                        if cracked:
                            break
                    c2 = chars[i2]
                    i2 += 1
                    i3 = 0
                    if cracked:
                        break
                c = chars[i]
                i += 1
                i2 = 0
                if cracked:
                    break

        if not error:
            ui.clear()
            print("Cracked!")
            print("The password is: " + guess)
            print("Tried " + str(loops) + " combinations in " +
                  str(round(timeNow - startTime, 2)) + " seconds.")
            if timeNow == startTime:
                timeNow += 1
            print("An average of " +
                  str(round(loops / (timeNow - startTime), 2)) + "pw/s")
        else:
            print("Unable to crack password, please make sure the hash is in SHA-1.\n")
            print("If the hash is in SHA-1, then the password is either longer than")
            print("10 characters, or contains a character that is not specified.")

    def portscan(self, remoteServer, maxport):

        def title():
            ui.clear()
            ui.divider()
            print(f"                        Port Scan for {remoteServer}")
            ui.divider()

        openPorts = 0
        ports = []
        remoteServerIP = socket.gethostbyname(remoteServer)
        socket.setdefaulttimeout(0.5)
        with Spinner():
            try:
                for port in range(1, maxport):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    result = sock.connect_ex((remoteServerIP, port))

                    if result == 0:
                        try:
                            s = socket.socket()
                            s.connect((remoteServerIP, port))
                            s.settimeout(0.1)
                            s.send(b"\n\n\n\n\n")
                            banner = str(s.recv(1024))
                            ports.append(str(port) + " - open >> " + banner)

                            title()
                            for x in ports:
                                print(x)
                            ui.divider()
                            openPorts = openPorts + 1
                        except:
                            ports.append(str(port) + " - open")
                            title()
                            for x in ports:
                                print(x)
                            ui.divider()
                            openPorts = openPorts + 1
                    sock.close()

                title()
                for x in ports:
                    print(x)
                ui.divider()
                print(f"{openPorts} open ports.")
                ui.divider()

            except KeyboardInterrupt:
                print("\n\nYou pressed Ctrl+C")
                sleepy.sleep(5)
                return

            except socket.gaierror:
                print('\n\nHostname could not be resolved. Exiting')
                sleepy.sleep(5)
                return

            except socket.error:
                print("\n\nCouldn't connect to server")
                sleepy.sleep(5)
                return

    def discovery(self):
        aliveHosts = []
        alive = 0
        net = self.localip
        net1 = net.split('.')
        net2 = net1[0] + '.' + net1[1] + '.' + net1[2] + '.'

        def ping_ip(current_ip_address):
            try:
                output = subprocess.check_output(
                    "ping -W 0.1 -{} 1 {}".format('n' if platform.system().lower() == "windows" else 'c',
                                                  current_ip_address), shell=True, universal_newlines=True)
                if 'unreachable' in output:
                    return False
                else:
                    return True

            except Exception:
                return False

        with Spinner():
            for x in range(1, 254):
                current = net2 + str(x)

                if ping_ip(current) == 1:
                    alive = alive + 1
                    aliveHosts.append(str(current))

                ui.title(f"Discovery for {net2}1/254")

                for host in aliveHosts:
                    print(f"Found: {host} (You)") if self.localip in host else print(
                        f"Found: {host}")

        ui.footer(f"{alive} hosts alive.")
        input("\n\nPress enter to return to menu.")

    def both(self):

        def end():
            ui.divider()
            print(f"{alive} hosts alive.")
            ui.divider()
            input("\nPress enter to return to menu.")

        def ping_ip(current_ip_address):
            try:
                output = subprocess.check_output(
                    "ping -W 0.1 -{} 1 {}".format('n' if platform.system().lower() == "windows" else 'c',
                                                  current_ip_address), shell=True, universal_newlines=True)
                if 'unreachable' in output:
                    return False
                else:
                    return True
            except Exception:
                return False

        aliveHosts = []
        alive = 0
        net = self.localip
        net1 = net.split('.')
        baseIP = net1[0] + '.' + net1[1] + '.' + net1[2] + '.'

        ui.title(f"Discovery & Port Scan for {baseIP}1/254 (Ports 1 - 1000)")

        for x in range(1, 254):
            current = baseIP + str(x)
            if ping_ip(current) == 1:
                alive = alive + 1
                aliveHosts.append(str(current))

                if self.localip in current:
                    openPorts = 0
                    print(f"Found: {current} (You):")

                    try:
                        for port in range(1, 1000):
                            sock = socket.socket(
                                socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(0.1)
                            result = sock.connect_ex((current, port))

                            if result == 0:
                                try:
                                    s = socket.socket()
                                    s.connect((current, port))
                                    s.settimeout(0.1)
                                    s.send(b"\n\n\n\n\n")
                                    banner = str(s.recv(1024))
                                    print(
                                        f" [+] Port {port} - open >> {banner}")
                                    openPorts = openPorts + 1
                                except:
                                    print(f" [+] Port {port} - open")
                                    openPorts = openPorts + 1

                            sock.close()
                        print(f" [=] {openPorts} open ports.\n")

                    except KeyboardInterrupt:
                        print("\n\nYou pressed Ctrl+C")
                        sleepy.sleep(5)
                        return

                    except socket.gaierror:
                        print('\n\nHostname could not be resolved. Exiting')
                        sleepy.sleep(5)
                        return

                    except socket.error:
                        print("\n\nCouldn't connect to server")
                        sleepy.sleep(5)
                        return

                elif self.localip not in current:
                    openPorts = 0
                    print(f"Found: {current}:")
                    try:
                        for port in range(1, 1000):
                            sock = socket.socket(
                                socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(0.1)
                            result = sock.connect_ex((current, port))

                            if result == 0:
                                try:
                                    s = socket.socket()
                                    s.connect((current, port))
                                    s.settimeout(0.1)
                                    s.send(b"\n\n\n\n\n")
                                    banner = str(s.recv(1024))
                                    print(
                                        f" [+] Port {port} - open >> {banner}")
                                    openPorts = openPorts + 1
                                except:
                                    print(f" [+] Port {port} - open")
                                    openPorts = openPorts + 1

                            sock.close()
                        print(f" [=] {openPorts} open ports.\n")

                    except KeyboardInterrupt:
                        print("\n\nYou pressed Ctrl+C")
                        sleepy.sleep(5)
                        return

                    except socket.gaierror:
                        print('\n\nHostname could not be resolved. Exiting')
                        sleepy.sleep(5)
                        return

                    except socket.error:
                        print("\n\nCouldn't connect to server")
                        sleepy.sleep(5)
                        return

        end()

    def networkscan(self):
        menulist = ["1. Discover alive hosts", "2. Single host portscan", "3. Discover & Portscan (Takes a long time)",
                    "\n0. Back"]

        active = True
        while active:
            ui.title("Network Scan")
            for item in menulist:
                print(item)
            ui.divider()
            choice = input("Select an option: ")

            if choice == "1":
                ui.title("Network Discovery")
                self.discovery()
                pass

            if choice == "2":
                ui.title("Single Host Port Scan")
                remoteServer = input("Enter IP address: ")
                self.portscan(remoteServer, 60000)
                input("\nPress enter to return.")

            if choice == "3":
                self.both()

            elif choice == "0":
                return


class Main:
    def __init__(self):
        tools.login()
        tools.depcheck("requests")
        # tools.depcheck("colorama")
        tools.splashScreen()

        try:
            file = open("passwords.txt", "r")
            file.close()
        except:
            ui.clear()
            ui.write("Downloading password file.", 0.005)
            with Spinner():
                file = urllib.request.urlretrieve('https://www.scrapmaker.com/data/wordlists/dictionaries/rockyou.txt',
                                                  './passwords.txt')

        while True:
            self.menu()

    def menu(self):

        menulist = ["1. Local Machine", "2. Network", "\n0. Exit"]

        ui.title("Main Menu")
        for item in menulist:
            print(item)

        ui.divider()
        choice = input("\nSelect an option: ")

        if choice == "1":
            LocalMachine()
        elif choice == "2":
            Network()
        elif choice == "0":
            ui.clear()
            exit(0)


ui = UI()
tools = Tools()
main = Main()

for word in passwordlist:
    print(word)
