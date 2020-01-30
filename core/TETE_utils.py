#!/usr/bin/python3
# -*- coding: UTF-8 -*-

## These are the obfuscations of the TE header and the chunked directive, necessary for the TE.TE scan. First item in both lists are standard header and value.
## SMUGGLEtest tests every possible combination of obfuscated TE headers and values in order to detect a vulnerability.

TE_Header_Obfuscations = ['Transfer-Encoding', 'Transfer-Encoding\r\n', 'Transfer-Encoding\' Transfer-Encoding',
                          'Transfer-Encoding ',
                          'Transfer-encoding', 'TrAnSfEr-EnCoDiNg']
chunked_obfuscations = ['chunked', '\r\nchunked', 'chunked\r\nTransfer-encoding: cow', 'xchunked', ' chunked',
                        '\tchunked',
                        'chunk', 'chu', 'identity',
                        '\"chunked\"', 'chùnked', '\x00chunked', 'chunked:chunked', 'x',
                        'identity, chunked', 'cow']
