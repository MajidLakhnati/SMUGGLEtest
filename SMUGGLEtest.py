#!/usr/bin/python3
# -*- coding: UTF-8 -*-

## Imports from the scans and patches directories

import patches.patching
from scans.hrs_scans import SMUGGLE_SCAN

## These imports are necessary for SMUGGLEtest itself.

import requests
import argparse
from argparse import RawTextHelpFormatter
import signal

# -------------------------------------------------------------------------------------------------
# usage of the program with argparse
def CLI():
    parser = argparse.ArgumentParser(
        description="A simple HTTP Request Smuggling Scanner\n"
                    "Author: Majid Lakhnati\n"
                    "Version: 1.0\n"
                    "License: GPLv3\n"
                    "Based on the work of James Kettle (https://skeletonscribe.net/)\n"
                    
                    "\n\n-------------------HOTKEYS-------------------\n"
                    "\nCTRL+C = Stop SMUGGLEtest"
        "\n\n-------------------USAGE-------------------\n"
        "\nSingle URL: python3 SMUGGLEtest.py -u http://example.com\n"
        "Input file: python3 SMUGGLEtest.py -i example.txt"
        "\n\n-------------------ARGUMENTS-------------------\n",
        formatter_class=RawTextHelpFormatter)
    parser.add_argument("-u", help='target URL', dest='url')
    parser.add_argument("-i", help="File with domain or URL list", dest='infile')
    return parser.parse_args()

# -------------------------------------------------------------------------------------------------
def main():
    global args
    args = CLI()
    patches.patching.patch_regex()                                                    ## patch the regexs to accomplish the obfuscation of the Transfer-Encoding header
    requests.models.PreparedRequest.prepare_body = patches.patching.patch_prepare_body  ## overwrite the prepare_body function in requests.models.py
    if args.infile:
        try:
            infile = args.infile
            urls = [line.rstrip() for line in open(infile)]
            outputFile = map(SMUGGLE_SCAN, urls)
            return list(outputFile)
        except (IOError, ValueError) as e:
            print(e)
            return
        except KeyboardInterrupt:
            pass
            print("SMUGGLEtest has been interrupted. Now terminating..")
    if args.url:
        url = args.url
        try:
            return SMUGGLE_SCAN(url)
        except KeyboardInterrupt:
            pass
            print("SMUGGLEtest has been interrupted. Now terminating..")
# -------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
