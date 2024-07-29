#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import os
import pathlib
import subprocess

from Crypto.Random import get_random_bytes

from constants import *

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")

# lengths for secrets
AES_KEY_LEN = 32
TAG_LEN = 16

def make_bootloader() -> bool:

    # create secrets txt file for fw_protect
    with open(BUILD_OUTPUT_PATH, "wb") as secrets_txt:
        # create aes key and c array format
        aes_key = get_random_bytes(AES_KEY_LEN)
        c_aes_key = ', '.join(f'0x{byte:02x}' for byte in aes_key)

        # create secrets header for bootloader and write
        with open(SECRETS_PATH, "w") as secrets_header:
            # write dependencies
            secrets_header.write(f'#include <stdlib.h>\n')

            # write lengths
            secrets_header.write(f'#define AES_KEY_LEN {AES_KEY_LEN}\n')
            secrets_header.write(f'#define TAG_LEN {TAG_LEN}\n')

            # write aes key within "aes_key" section of compiled binary
            secrets_header.write(f'uint8_t AES_KEY[] = {{{c_aes_key}}};\n')

        # write to secrets text file
        secrets_txt.write(aes_key)

    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0

#TODO: Beg Iv for Internship

if __name__ == "__main__":
    make_bootloader()