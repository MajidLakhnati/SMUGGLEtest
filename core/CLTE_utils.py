#!/usr/bin/python3
# -*- coding: UTF-8 -*-

def CLTE_generator():
    var1 = "5\r\n"
    var2 = "x=F00\r\n"
    var3 = "X\r\n\r\n"
    a = var1.encode('utf8')
    b = var2.encode('utf8')
    c = var3.encode('utf8')
    yield a
    yield b
    yield c

## These dicts generate us the headers for scanning a CL.TE vuln. One normal request and one that (hopefully) triggers a timeout.

CLTE_headers_Normal = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0',
    'Connection': 'keep-alive', 'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': '15',
    'Transfer-Encoding': 'chunked'}
CLTE_headers_TimeOut = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0',
    'Connection': 'keep-alive', 'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': '8'}