#!/usr/bin/env python3

import argparse
import hashlib
import binascii
from passlib.hash import msdcc2
from impacket.ntlm import compute_lmhash, compute_nthash


def get_arguments():
    parser = argparse.ArgumentParser(
        description="Generate NTLM and other hashes for provided credentials."
    )
    parser.add_argument(
        "-p", "--password", required=True, help="Provide a password to hash."
    )
    parser.add_argument(
        "-u",
        "--username",
        required=True,
        help="Provide a username for hashing (needed for MSDCC2 hash).",
    )
    return parser.parse_args()


def display_hashes(password, username):
    lm_hash = binascii.hexlify(compute_lmhash(password)).decode()
    nt_hash = binascii.hexlify(compute_nthash(password)).decode()
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    msdcc2_hash = msdcc2.hash(password, username)

    print("[+] LM HASH: " + lm_hash)
    print("[+] NT HASH: " + nt_hash)
    print("[+] SHA1 HASH: " + sha1_hash)
    print("[+] MSDCC2 HASH: " + msdcc2_hash)


def main():
    options = get_arguments()
    display_hashes(options.password, options.username)


if __name__ == "__main__":
    main()
