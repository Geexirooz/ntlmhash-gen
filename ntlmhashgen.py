#!/usr/bin/env python3

import argparse
import hashlib
import binascii
from passlib.hash import msdcc2
from impacket.ntlm import compute_lmhash, compute_nthash
from colorama import Fore, Style, init
import random

init()  # Initializes Colorama

def get_arguments():
    parser = argparse.ArgumentParser(description='Generate NTLM and other hashes for provided credentials.')
    parser.add_argument("-p", "--password", required=True, help="Provide a password to hash.")
    parser.add_argument("-u", "--username", required=True, help="Provide a username for hashing (needed for MSDCC2 hash).")
    return parser.parse_args()

def print_banner():
    colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
    banner_color = random.choice(colors)
    banner = """
 _   _ _____ _     __  __   _   _    _    ____  _   _    ____ _____ _   _ 
| \ | |_   _| |   |  \/  | | | | |  / \  / ___|| | | |  / ___| ____| \ | |
|  \| | | | | |   | |\/| | | |_| | / _ \ \___ \| |_| | | |  _|  _| |  \| |
| |\  | | | | |___| |  | | |  _  |/ ___ \ ___) |  _  | | |_| | |___| |\  |
|_| \_| |_| |_____|_|  |_| |_| |_/_/   \_\____/|_| |_|  \____|_____|_| \_|
    """
    print(banner_color + banner + Style.RESET_ALL)
    print(banner_color + "Created By: H088yHaX0R - 2020" + Style.RESET_ALL)
    print("\n")

def display_hashes(password, username):
    colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
    text_color = random.choice(colors)
    lm_hash = binascii.hexlify(compute_lmhash(password)).decode()
    nt_hash = binascii.hexlify(compute_nthash(password)).decode()
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    msdcc2_hash = msdcc2.hash(password, username)

    print(text_color + "[*] Password To Hash: " + password + Style.RESET_ALL)
    print(text_color + "[*] Username To Hash: " + username + Style.RESET_ALL)
    print(text_color + "[+] LM HASH: " + lm_hash + Style.RESET_ALL)
    print(text_color + "[+] NT HASH: " + nt_hash + Style.RESET_ALL)
    print(text_color + "[+] SHA1 HASH: " + sha1_hash + Style.RESET_ALL)
    print(text_color + "[+] MSDCC2 HASH: " + msdcc2_hash + Style.RESET_ALL)

def main():
    options = get_arguments()
    print_banner()
    display_hashes(options.password, options.username)

if __name__ == "__main__":
    main()
