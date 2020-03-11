#!/usr/bin/python3
# -*- coding: UTF-8 -*-

# -------------------------------------------------------------------------------------------------
## This generates us the desired HTTP message body for the Transfer-Encoding.Content-Length (TE.CL) Scan.

def tecl_generator():
    var4 = "0\r\n"
    var5 = "\r\n"
    var6 = "X\r\n\r\n"
    x = var4.encode('utf8')
    y = var5.encode('utf8')
    z = var6.encode('utf8')
    yield x
    yield y
    yield z


## This dicts generate us the headers for scans a TE.CL vuln. We just need the timeout request at this point.

tecl_headers_timeout = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0',
    'Connection': 'keep-alive', 'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': '6',
    'Transfer-Encoding': 'chunked'}

