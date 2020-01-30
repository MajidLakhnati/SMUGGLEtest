#!/usr/bin/python3
# -*- coding: UTF-8 -*-

## Imports from core

from core.patching_SMUGGLEtest import patch_prepare_body, patch_filters
from core.CLTE_utils import CLTE_generator, CLTE_headers_Normal, CLTE_headers_TimeOut
from core.TECL_utils import TECL_generator, TECL_headers_TimeOut
from core.TETE_utils import TE_Header_Obfuscations, chunked_obfuscations
from core.colours import colours

## These imports are necessary for SMUGGLEtest itself.

import requests
import argparse
from argparse import RawTextHelpFormatter
import signal
from urllib.parse import urlparse

# -------------------------------------------------------------------------------------------------
# usage of the program with argparse
def usage():
    parser = argparse.ArgumentParser(
        description="Simple HTTP Request Smuggling Scanner\nAuthor: Majid Lakhnati\nVersion: 1.0\nLicense: GPLv3\nBased on the work of James Kettle (https://skeletonscribe.net/)\n\n-------------------HOTKEYS-------------------\nCTRL+C = Stop SMUGGLEtest",
        formatter_class=RawTextHelpFormatter)
    parser.add_argument("-u", help='target URL', dest='url')
    parser.add_argument("-i", help="File with domain or URL list", dest='infile')
    return parser.parse_args()

# -------------------------------------------------------------------------------------------------
def main():
    global args
    args = usage()
    patch_filters()                                                    ## patch filters to accomplish the obfuscation of the Transfer-Encoding header
    requests.models.PreparedRequest.prepare_body = patch_prepare_body  ## overwrite the prepare_body function in requests.models.py
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
    else:
        print(
            colours.bad + colours.red + " No parameters were provided for SMUGGLEtest. Either use 'python3 SMUGGLEtest.py -u <URL>' or 'python3 SMUGGLEtest.py -i <INPUTFILE>'!\n"
                                        "In case of help: 'python3 SMUGGLEtest.py -h'")
    sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGINT, sigint_handler)  # calling signal handler

# -------------------------------------------------------------------------------------------------

## The function SMUGGLE_SCAN is the main function of SMUGGLEtest. It scans the passed url for CL.TE, TE.CL and TE.TE vulnerabilites
## TE.TE vulnerabilities are those where the TE header is obfuscated in some way and one of the servers in the chain therefore falls back to CL.TE or TE.CL. This achieves the desired desync.

def SMUGGLE_SCAN(url):
    checkURL = urlparse(url)
    print(colours.info + " Currently scanning %s\n" % url)
    if checkURL.scheme == 'http':
        pass
    elif checkURL.scheme == 'https':
        pass
    else:
        print(colours.bad + " No HTTP or HTTPS scheme was provided with the following URL: '%s'" % url)
        print(colours.info + " Please use another URL/endpoint that can be accessed by SMUGGLEtest.")

# -------------------------------------------------------------------------------------------------
## SMUGGLEtest first issues the normal request to check if an error occurs.

    CLTE_response_Normal = requests.post(url=url, data=CLTE_generator(), headers=CLTE_headers_Normal)

    # Status Code errors
    if CLTE_response_Normal.status_code == 404:
        print(colours.bad + " Received a 404 error message (Not found) when accessing the following URL: '%s'" % url)
        print(colours.info + " Please use another URL/endpoint that can be accessed by SMUGGLEtest.\n")
        return
    elif CLTE_response_Normal.status_code == 405:
        print(
            colours.bad + " Received a 405 error message (Method not allowed) when accessing the following URL: '%s'" % url)
        print(
            colours.info + " The URL that SMUGGLEtest tried to scan does not support POST methods. Please use another URL/endpoint that can be accessed by SMUGGLETEST.\n")
        return
    elif CLTE_response_Normal.status_code == 301:
        print(
            colours.bad + " Received a 301 error message (Moved permanently) when accessing the following URL: '%s'" % url)
        print(
            colours.info + " The resource under the URL that SMUGGLEtest tried to scan has been moved permanently. Please use another URL/endpoint that can be accessed by SMUGGLETEST.\n")
        return
    # HTTP version errors
    if CLTE_response_Normal.raw.version != 11:
        print(
            colours.bad + " Received an error message when accessing the following URL: '%s'" % url)
        print(
            colours.info + " The web server that SMUGGLEtest tried to scan does not use HTTP/1.1. Please use another URL/endpoint that supports HTTP/1.1 and the Keep-Alive method.\n")
        return

    # Here, the real detection of the vulnerabilties takes place.

    for x in TE_Header_Obfuscations:                                  ## loop for iterating through TE header list
        for y in chunked_obfuscations:                                ## loop for iterating through TE value list
            CLTE_headers_TimeOut[x] = y                               ## SMUGGLEtest first scans for CL.TE because the TE.CL scan could poison the back-end if a CL.TE vuln exists.
            CLTE_response = requests.post(url=url, data=CLTE_generator(),  ## CL.TE Scan
                                          headers=CLTE_headers_TimeOut, timeout=15)
            if CLTE_response.elapsed.total_seconds() > 7:  ## Vulnerability has been found in case of a time out.
                print(
                    colours.good + colours.yellow + " Vulnerability:",
                    colours.white + " A Content-Length.Transfer-Encoding (CL.TE) vulnerability has been found!")
                print(colours.info + colours.yellow + " URL:", colours.white + " '%s'" % url)
                print(
                    colours.info + colours.yellow + " Description:",
                    colours.white + " SMUGGLEtest sent one request twice, but the second request with a shorter Content-Length. \n "
                                    "The server response to the second request took longer than the first one. "
                                    "This indicates that the front-end and back-end server are desynchronized. \n "
                                    "In this case, the front-end server parses the Content-Length header and the back-end server parses the Transfer-Encoding header.")
                if x == 'Transfer-Encoding' and y == 'chunked':
                    print(
                        colours.info + colours.yellow + " Type:",
                        colours.white + " Basic. No obfuscation of the Transfer-Encoding header is necessary to exploit this. \n "
                                        "When exploiting this, just use the standard Transfer-Encoding: chunked")
                    print(colours.info + colours.yellow + " Transfer-Encoding header:",
                          colours.white + " '%s: %s'" % (x, y))
                else:
                    print(
                        colours.info + colours.yellow + " Type:",
                        colours.white + " Advanced. An obfuscation of the Transfer-Encoding header is necessary to exploit this.")
                    print(colours.info + colours.yellow + " Transfer-Encoding header:",
                          colours.white + " '%s: %s'" % (x, y))
                print(
                    colours.info + colours.yellow + " Exploitation:",
                    colours.white + " https://portswigger.net/web-security/request-smuggling/exploiting\n\n")
                CLTE_headers_TimeOut.pop(x)                               ## Remove TE header for (possible) next iteration of the loop.
                return
            else:
                CLTE_headers_TimeOut.pop(x)
                TECL_headers_TimeOut[x] = y                               ## If CL.TE failed, SMUGGLEtest can safely try the TE.CL scan with the same TE header.
                TECL_response = requests.post(url=url, data=TECL_generator(),  ## TE.CL Scan
                                              headers=TECL_headers_TimeOut, timeout=15)
                if TECL_response.elapsed.total_seconds() > 7:
                    print(colours.good + colours.yellow + " Vulnerability:",
                          colours.white + " A Transfer-Encoding.Content.Length (TE.CL) vulnerability has been found!")
                    print(colours.info + colours.yellow + " URL:",
                          colours.white + " '%s'" % url)
                    print(
                        colours.info + colours.yellow + " Description:",
                        colours.white + " Description: SMUGGLEtest sent one request twice, but the second request with a longer Content-Length and a closing chunk.\n"
                                        "The server response to the second request took longer than the first one. "
                                        "This indicates that the front-end and back-end server are desynchronized. \n "
                                        "In this case, the front-end server parses the Transfer-Encoding header and the back-end server parses the Content-Length header.")
                    if x == 'Transfer-Encoding' and y == 'chunked':
                        print(
                            colours.info + colours.yellow + " Type:",
                            colours.white + " Basic. No obfuscation of the Transfer-Encoding header is necessary to exploit this. \n "
                                            "When exploiting this, just use the standard Transfer-Encoding: chunked")
                    else:
                        print(
                            colours.info + colours.yellow + " Type:",
                            colours.white + " Advanced. An obfuscation of the Transfer-Encoding header is necessary to exploit this.")
                    print(colours.info + colours.yellow + " Transfer-Encoding header:",
                          colours.white + " '%s: %s'" % (x, y))
                    print(
                        colours.info + colours.yellow + " Exploitation:",
                        colours.white + " https://portswigger.net/web-security/request-smuggling/exploiting\n\n")
                    TECL_headers_TimeOut.pop(x)
                    return
                else:
                    TECL_headers_TimeOut.pop(x)
                    ## Scanning continues UNTIL last elements of TE_Header_Obfuscations and chunked_obfuscations were tested.
                    list_index1 = TE_Header_Obfuscations.index(x)
                    list_index2 = chunked_obfuscations.index(y)
                    list_len1 = len(TE_Header_Obfuscations)
                    list_len2 = len(chunked_obfuscations)
                    list_end1 = list_len1 - list_index1
                    list_end2 = list_len2 - list_index2
                    if list_end1 == 1 and list_end2 == 1:  ## determine end of the lists
                        print(colours.bad + colours.yellow + " No vulnerabilties were found for URL:",
                              colours.white + " '%s'" % url)
                    else:
                        pass
# -------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
