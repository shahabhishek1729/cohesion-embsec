#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import os

# Challenge constraints
FIRMWARE_MAX = 30000
MESSAGE_MAX = 1000

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()

    # Check constraints and reject everything that disobeys them
    if len(firmware) > FIRMWARE_MAX:
        raise ValueError("Firmware is too big sneaky boi")
    
    if len(message) > MESSAGE_MAX:
        raise ValueError("Message needs to lose some pounds, and not the british ones")
    
    # format firmware
    firmware_packed = p16(version, endian='little') + p16(len(firmware), endian='little')
    firmware_packed = firmware_packed + firmware + message.encode(encoding="ascii")
    firmware_packed = firmware_packed + b"\00"
    
    # pad firmware
    firmware_packed = pad(firmware_packed, AES.block_size)

    # TODO: Replace with key file
    with open("/home/hacker/cohesion-embsec/tools/secret_build_output.txt", "rb") as secrets_txt:
        key = secrets_txt.read()

    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce

    ciphertext, tag = cipher.encrypt_and_digest(firmware_packed)

    # encrypted_message = nonce + tag + ciphertext
    # length of nonce and tag is 16
    firmware_blob = nonce + tag + ciphertext

    os.remove("/home/hacker/cohesion-embsec/bootloader/inc/secrets.h")
    os.remove("/home/hacker/cohesion-embsec/tools/secret_build_output.txt")

    # Write firmware blob to outfile
    with open(outfile, "wb+") as outfile:
        outfile.write(firmware_blob)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)



