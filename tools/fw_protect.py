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
from base64 import b64encode

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
       firmware = pad(fp.read(), 250)

    # Write code here
    header = b'\x00\x00\x00'
    key = open('secret_key.txt', 'rb').read()

    protected_firmware = ''

    for chunk in range(0, len(firmware), 250):
        chunk = firmware[chunk:chunk+250]
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.update(header)
        nonce = cipher.nonce


        ciphertext, tag = cipher.encrypt_and_digest(header + chunk)
        encrypted_message = b64encode(nonce + tag + ciphertext).decode('utf-8')

    # Append null-terminated message to end of firmware
    firmware_and_message = protected_firmware.encode() + b"\00"

    # Pack version and size into two little-endian shorts
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')  

    # Append firmware and message to metadata
    firmware_blob = metadata + firmware_and_message

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
