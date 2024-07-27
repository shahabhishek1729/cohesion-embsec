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


def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()

    # format firmware
    firmware_packed = p16(version, endian='little') + p16(len(message)) + message.encode(encoding="ascii")
    firmware_packed = firmware_packed + p16(len(firmware), endian='little') + firmware + b"\00"
    
    # pad firmware
    firmware_packed = pad(firmware_packed, AES.block_size)

    # TODO: Replace with key file
    key = b"Segmentation fault (core dumped)"
    assert len(key) == 32

    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce

    print(f"The nonce is {nonce} bytes long")
    print(f"Pre-encryption: {firmware_packed[:30]}")
    ciphertext, tag = cipher.encrypt_and_digest(firmware_packed)
    print(f"Post-encryption: {ciphertext[:30]}")

    import sys
    # encrypted_message = nonce + tag + ciphertext
    # length of nonce and tag is 16
    firmware_blob = nonce + tag + ciphertext

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