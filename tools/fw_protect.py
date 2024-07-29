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
from constants import * 

import os

def protect_firmware(infile: str, outfile: str, version: int, message: str) -> None:
    """ Read in firmware from a specified file, and write its encrypted form to another file.

    Based on the firmware specified in the file `infile`, this function appends metadata to this
    firmware and writes an encrypted blob to `outfile`. The output file should have data in the 
    following form:
    ---------------------------------------------------------------------------------------------------
    |  16 bytes  |  16 bytes  |  2 bytes    |  2 bytes          |  Variable  |  Variable  |  Variable  | 
    |  Nonce     |  Auth Tag  |  Version #  |  Firmware Length  |  Firmware  |  Message   |  Padding   |
    ---------------------------------------------------------------------------------------------------
    <----- Plaintext --------> <--------------------------- Encrypted --------------------------------->

    Args:
        infile (str): The path to the file in which the firmware is stored (in plaintext)
        outfile (str): The path to which the encrypted blob shown above will be written
        version (int): The nonnegative version number of the firmware (0 represents a debug version)
        message (str): The message stored along with the firmware, typically stating the changes made
    """
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()

    # Check constraints and reject everything that disobeys them
    if len(firmware) > FIRMWARE_MAX:
        raise ValueError(f"Firmware is too big sneaky boi: the max size allowable is {FIRMWARE_MAX} bytes, you sent in {len(firmware)} bytes")
    
    if len(message) > MESSAGE_MAX:
        raise ValueError(f"Message needs to lose some pounds, and not the british ones: the max size allowable is {MESSAGE_MAX} bytes, you sent in {len(message)} bytes")
    
    # format firmware
    firmware_packed = p16(version, endian='little') + p16(len(firmware), endian='little')
    firmware_packed += firmware + message.encode(encoding=DEFAULT_ENCODING)
    firmware_packed += b"\00"
    
    # pad firmware
    firmware_packed = pad(firmware_packed, AES.block_size)

    with open(BUILD_OUTPUT_PATH, "rb") as secrets_txt:
        key = secrets_txt.read()

    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce

    ciphertext, tag = cipher.encrypt_and_digest(firmware_packed)

    # encrypted_message = nonce + tag + ciphertext
    # length of nonce and tag is 16
    firmware_blob = nonce + tag + ciphertext

    os.remove(SECRETS_PATH)
    os.remove(BUILD_OUTPUT_PATH)

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



