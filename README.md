# **NTLM Hash Generator Script**

## Overview

This Python script is designed to generate several types of hashes for given credentials. It specifically computes LM and NT hashes using the NTLM protocol, SHA1 hashes, and Microsoft Domain Cached Credentials (MSDCC2) hashes, which are useful for network security testing and penetration testing tasks.

## Installation

Clone this repository or download the script to your local machine. Make sure all required libraries are installed:

```bash
git clone https://github.com/Geexirooz/ntlmhash-gen.git
cd ntlmhash-gen
pip install -r requirements.txt
```


## Usage

The script is executed from the command line with the following parameters:

* **-p**, **--password:** Specifies the password to hash.
* -**u**, **--username:** Specifies the username for which to compute the MSDCC2 hash (necessary for generating this type of hash).

```bash
python ntlm_hash_generator.py -u username -p password
```
