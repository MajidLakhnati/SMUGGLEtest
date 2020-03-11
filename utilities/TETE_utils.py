#!/usr/bin/python3
# -*- coding: UTF-8 -*-

## These are the obfuscations of the TE header and the chunked directive, necessary for the TE.TE scan. First item in both lists are standard header and value.
## SMUGGLEtest tests every possible combination of obfuscated TE headers and values in order to detect a vulnerability.

te_header_obfuscations = ['Transfer-Encoding',                                                             # standard
                          'Transfer-Encoding\r\n', '\r\nTransfer-Encoding',                               # Line Feed
                          ' Transfer-Encoding', 'Transfer-Encoding ',                                     # whitespace
                          'Transfer-Encoding\t', '\tTransfer-Encoding',                                   # tab
                          'Transfer-encoding', 'TrAnSfEr-EnCoDiNg' ]                                      # case sensitive

chunked_obfuscations = [ 'chunked',                                                                       # standard
                         '\r\nchunked', 'chunked\r\n',                                                    # Line Feed
                         '\rchunked', 'chunked\r',                                                        # carriage return
                         ' chunked', 'chunked ',                                                          # whitespace
                         '\tchunked', 'chunked\t',                                                         # tab
                         'chunked\r\nTransfer-Encoding: foo', 'chunked\r\nTransfer-encoding: foo',        # duplicate header
                         'chunked, identity', 'identity, chunked',                                        # whitelisted identity
                         'zchunked', 'xchunked', 'chunk', 'chu', 'chùnked', '\x00chunked' ]               # miscellaneous

