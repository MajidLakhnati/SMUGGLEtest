from utilities.CLTE_utils import clte_generator, clte_headers_normal, clte_headers_timeout
from utilities.TECL_utils import tecl_generator, tecl_headers_timeout
from utilities.TETE_utils import te_header_obfuscations, chunked_obfuscations
from utilities.colours import colours

import requests


def SMUGGLE_SCAN(url):
    print(colours.info + " Currently scanning %s\n" % url)
    # -------------------------------------------------------------------------------------------------
    ## SMUGGLEtest first issues the normal request to check if an error occurs.
    clte_response_Normal = requests.post(url=url, data=clte_generator(), headers=clte_headers_normal, timeout=15)

    # Status Code errors
    if clte_response_Normal.status_code == 404:
        print(colours.bad + " Received a 404 error message (Not found) when accessing the following URL: '%s'" % url)
        print(colours.info + " Please use another URL/endpoint that can be accessed by SMUGGLEtest.\n")
        return
    elif clte_response_Normal.status_code == 405:
        print(
            colours.bad + " Received a 405 error message (Method not allowed) when accessing the following URL: '%s'" % url)
        print(
            colours.info + " The URL that SMUGGLEtest tried to scan does not support POST methods. Please use another URL/endpoint that can be accessed by SMUGGLETEST.\n")
        return
    elif clte_response_Normal.status_code == 301:
        print(
            colours.bad + " Received a 301 error message (Moved permanently) when accessing the following URL: '%s'" % url)
        print(
            colours.info + " The resource under the URL that SMUGGLEtest tried to scan has been moved permanently. Please use another URL/endpoint that can be accessed by SMUGGLETEST.\n")
        return
    # HTTP version errors
    if clte_response_Normal.raw.version != 11:
        print(
            colours.bad + " Received an error message when accessing the following URL: '%s'" % url)
        print(
            colours.info + " The web server that SMUGGLEtest tried to scan does not use HTTP/1.1. Please use another URL/endpoint that supports HTTP/1.1 and the Keep-Alive method.\n")
        return

    # Here, the real detection of the vulnerabilties takes place.

    for x in te_header_obfuscations:  ## loop for iterating through TE header list
        for y in chunked_obfuscations:  ## loop for iterating through TE value list
            clte_headers_timeout[
                x] = y  ## SMUGGLEtest first scans for CL.TE because the TE.CL scan could poison the back-end if a CL.TE vuln exists.
            clte_response = requests.post(url=url, data=clte_generator(),  ## CL.TE Scan
                                          headers=clte_headers_timeout)

            if clte_response.elapsed.total_seconds() >= 8:  ## Vulnerability has been found in case of a time out.
                print(
                    colours.good + colours.yellow + " Vulnerability:",
                    colours.white + " A Content-Length.Transfer-Encoding (CL.TE) vulnerability has been found!")
                print(colours.info + colours.yellow + " URL:", colours.white + " '%s'" % url)
                print(
                    colours.info + colours.yellow + " Description:",
                    colours.white + " SMUGGLEtest sent a request that front-end and back-end interpreted differently.\n "
                                    "The front-end accepted the received request as valid, but only forwarded a part of the message to the back-end.\n "
                                    "The back-end received this request, but expected a longer message according to the HTTP headers.\n "
                                    "The consequences is that the back-end waits for the rest of the message to arrive.\n "
                                    "This causes a time out that SMUGGLEtest deteced.\n "
                                    "In this case, the front-end server parses the Content-Length header and the back-end server parses the Transfer-Encoding header.")
                if x == 'Transfer-Encoding' and y == 'chunked':
                    print(
                        colours.info + colours.yellow + " Complexity:",
                        colours.white + " Basic. No obfuscation of the Transfer-Encoding header is necessary to exploit this. \n "
                                        "When exploiting this, just use the standard Transfer-Encoding: chunked")
                    print(colours.info + colours.yellow + " Transfer-Encoding header:",
                          colours.white + " '%s: %s'" % (x, y))
                else:
                    print(
                        colours.info + colours.yellow + " Complexity:",
                        colours.white + " Advanced. An obfuscation of the Transfer-Encoding header is necessary to exploit this.")
                    print(colours.info + colours.yellow + " Transfer-Encoding header:",
                          colours.white + " '%s: %s'" % (x, y))
                print(
                    colours.info + colours.yellow + " Exploitation:",
                    colours.white + " https://portswigger.net/web-security/request-smuggling/exploiting\n\n")
                clte_headers_timeout.pop(x)  ## Remove TE header for (possible) next iteration of the loop.
                return
            else:
                clte_headers_timeout.pop(x)
                tecl_headers_timeout[
                    x] = y  ## If CL.TE failed, SMUGGLEtest can safely try the TE.CL scan with the same TE header.
                tecl_response = requests.post(url=url, data=tecl_generator(),  ## TE.CL Scan
                                              headers=tecl_headers_timeout)

                if tecl_response.elapsed.total_seconds() >= 8:
                    print(colours.good + colours.yellow + " Vulnerability:",
                          colours.white + " A Transfer-Encoding.Content.Length (TE.CL) vulnerability has been found!")
                    print(colours.info + colours.yellow + " URL:",
                          colours.white + " '%s'" % url)
                    print(
                        colours.info + colours.yellow + " Description:",
                        colours.white + " SMUGGLEtest sent a request that front-end and back-end interpreted differently.\n "
                                    "The front-end accepted the received request as valid, but only forwarded a part of the message to the back-end.\n "
                                    "The back-end received this request, but expected a longer message according to the HTTP headers.\n "
                                    "The consequences is that the back-end waits for the rest of the message to arrive.\n "
                                    "This causes a time out that SMUGGLEtest detected.\n "
                                    "In this case, the front-end server parses the Transfer-Encoding header and the back-end server parses the Content-Length header.")
                    if x == 'Transfer-Encoding' and y == 'chunked':
                        print(
                            colours.info + colours.yellow + " Complexity:",
                            colours.white + " Basic. No obfuscation of the Transfer-Encoding header is necessary to exploit this. \n "
                                            "When exploiting this, just use the standard Transfer-Encoding: chunked")
                    else:
                        print(
                            colours.info + colours.yellow + " Complexity:",
                            colours.white + " Advanced. An obfuscation of the Transfer-Encoding header is necessary to exploit this.")
                    print(colours.info + colours.yellow + " Transfer-Encoding Header:",
                          colours.white + " '%s: %s'" % (x, y))
                    print(
                        colours.info + colours.yellow + " Exploitation:",
                        colours.white + " https://portswigger.net/web-security/request-smuggling/exploiting\n\n")
                    tecl_headers_timeout.pop(x)
                    return
                else:
                    tecl_headers_timeout.pop(x)
                    ## Scanning continues UNTIL last elements of te_header_obfuscations and chunked_obfuscations were tested.
                    list_index1 = te_header_obfuscations.index(x)
                    list_index2 = chunked_obfuscations.index(y)
                    list_len1 = len(te_header_obfuscations)
                    list_len2 = len(chunked_obfuscations)
                    list_end1 = list_len1 - list_index1
                    list_end2 = list_len2 - list_index2
                    if list_end1 == 1 and list_end2 == 1:  ## determine end of the lists
                        print(colours.bad + colours.yellow + " No vulnerabilties were found for URL:",
                              colours.white + " '%s'" % url)
                    else:
                        pass
