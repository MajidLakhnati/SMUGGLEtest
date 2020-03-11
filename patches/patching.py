#!/usr/bin/python3
# -*- coding: UTF-8 -*-

## These imports are necessary for monkey patching the function "prepare_body()", line 453 in requests.models.py

import requests

from io import UnsupportedOperation
from requests.compat import (Mapping, bytes, builtin_str, basestring)
from requests.utils import super_len
import http.client
import re
import json as complexjson


def patch_prepare_body(self, data, files,
                        json=None):  ## This is a monkey patch of the function "prepare_body" in lib requests.models.py. In line 501 of that file, the Requests Library attaches the header "Transfer-Encoding: chunked" by default if the sent message body is chunked encoded.
    """Prepares the given HTTP body data."""  ## This means that Requests always normalizes our obfuscated TE header to the standard TE header. To patch out this behavior, SMUGGLEtest took this function and commented the lines of code that are responsible for the normalization.
    # Check if file, fo, generator, iterator.
    # If not, run through normal process.
    # Nottin' on you.
    body = None
    content_type = None
    if not data and json is not None:
        # urllib3 requires a bytes-like body. Python 2's json.dumps
        # provides this natively, but Python 3 gives a Unicode string.
        content_type = 'application/json'
        body = complexjson.dumps(json)
        if not isinstance(body, bytes):
            body = body.encode('utf-8')
    is_stream = all([
        hasattr(data, '__iter__'),
        not isinstance(data, (basestring, list, tuple, Mapping))
    ])
    try:
        length = super_len(data)
    except (TypeError, AttributeError, UnsupportedOperation):
        length = None
    if is_stream:
        body = data
        if getattr(body, 'tell', None) is not None:
            # Record the current file position before reading.
            # This will allow us to rewind a file in the event
            # of a redirect.
            try:
                self._body_position = body.tell()
            except (IOError, OSError):
                # This differentiates from None, allowing us to catch
                # a failed `tell()` later when trying to rewind the body
                self._body_position = object()

        if files:
            raise NotImplementedError('Streamed bodies and files are mutually exclusive.')

        if length:
            self.headers['Content-Length'] = builtin_str(length)
        else:
            pass
            #self.headers['Transfer-Encoding'] = 'chunked'                        ## This would normalize the TE header. Thus, SMUGGLEtest replaced the line of code with a pass statement.

    else:
        # Multi-part file uploads.
        if files:
            (body, content_type) = self._encode_files(files, data)
        else:
            if data:
                body = self._encode_params(data)
                if isinstance(data, basestring) or hasattr(data, 'read'):
                    content_type = None
                else:
                    content_type = 'application/x-www-form-urlencoded'
        self.prepare_content_length(body)
        # Add content-type if it wasn't explicitly provided.
        if content_type and ('content-type' not in self.headers):
            self.headers['Content-Type'] = content_type
    self.body = body


# -------------------------------------------------------------------------------------------------
## It is also necessary to patch the filtering functions/patterns that prevents SMUGGLEtest from obfuscating the Transfer-Encoding header.

def patch_regex():
    ''''
    requests.utils._CLEAN_HEADER_REGEX_BYTE = re.compile(
        b'.*')  ## monkey patching the Regex that filters the Transfer-Encoding header value (bytes)
    '''
    requests.utils._CLEAN_HEADER_REGEX_STR = re.compile(
        r'.*?')  ##  monkey patching the Regex that filters the Transfer-Encoding header value (str)
    #http.client._is_legal_header_name = re.compile(
    #rb'.*?').search  ## monkey patching the Regex that filters the Transfer-Encoding header name  (for underlying httpclient)re.compile(
        #rb'.*').fullmatch
    http.client._is_legal_header_name = re.compile(
        rb'.*?').match
    http.client._is_illegal_header_value = re.compile(
    rb'$^').search  ## monkey patching the Regex that filters the Transfer-Encoding header value (for underlying httpclient)





