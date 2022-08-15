#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.parse

APP_HOST = "http://localhost:8080/api/v1"
SCAN_URL = APP_HOST + "/scan"
CSR_URL = APP_HOST + "/parse/csr"
CERT_URL = APP_HOST + "/parse/certificate"

ERRORS = 0
SUCCESS = 0

test_cases = {
    "nginx_good": {
        "exp_key_type": "ECDSA-384",
        "exp_server": "nginx/1.23.0",
        "exp_protocol_count": 2,
        "exp_cipher_count": {
            "TLSv1.2": 8,
            "TLSv1.3": 3
        },
        "exp_hbleed": {
            "vulnerable": False,
            "extension": False
        },
        "exp_ccsinjection": {
            "vulnerable": False
        }
    },
    "nginx_bad": {
        "exp_key_type": "RSA-2048",
        "exp_server": "nginx/1.2.9",
        "exp_protocol_count": 5,
        "exp_cipher_count": {
            "SSLv2": 7,
            "SSLv3": 36,
            "TLSv1.0": 36,
            "TLSv1.1": 36,
            "TLSv1.2": 52,
        },
        "exp_hbleed": {
            "vulnerable": True,
            "extension": True
        },
        "exp_ccsinjection": {
            "vulnerable": True
        }
    },
    "postfix_bad:25": {
        "exp_key_type": "RSA-2048",
        "exp_server": "220 mail.example.com ESMTP Postfix (Ubuntu)",
        "exp_protocol_count": 4,
        "exp_cipher_count": {
            "SSLv3": 38,
            "TLSv1.0": 38,
            "TLSv1.1": 38,
            "TLSv1.2": 54,
        },
        "exp_hbleed": {
            "vulnerable": False,
            "extension": True
        },
        "exp_ccsinjection": {
            "vulnerable": False
        }
    },
    "postfix_bad:587": {
        "exp_key_type": "RSA-2048",
        "exp_server": "220 mail.example.com ESMTP Postfix (Ubuntu)",
        "exp_protocol_count": 4,
        "exp_cipher_count": {
            "SSLv3": 29,
            "TLSv1.0": 29,
            "TLSv1.1": 29,
            "TLSv1.2": 45,
        },
        "exp_hbleed": {
            "vulnerable": False,
            "extension": True
        },
        "exp_ccsinjection": {
            "vulnerable": False
        }
    },
}

rsaCert = """-----BEGIN CERTIFICATE-----
MIIDbjCCAlagAwIBAgIBATANBgkqhkiG9w0BAQsFADBpMRkwFwYDVQQDDBBTZWxm
LVNpZ25lZCBSb290MQswCQYDVQQGEwJVUzELMAkGA1UECAwCV0ExFzAVBgNVBAcM
DlNvbWV3aGVyZSBDaXR5MRkwFwYDVQQKDBBTZWxmLVNpZ25lZCBJbmMuMB4XDTIx
MTEwOTAzMjIyNloXDTMxMTEwNzAzMjIyNlowajELMAkGA1UEBhMCVVMxCzAJBgNV
BAgMAldBMRcwFQYDVQQHDA5Tb21ld2hlcmUgQ2l0eTEZMBcGA1UECgwQU2VsZi1T
aWduZWQgSW5jLjEaMBgGA1UEAwwRdmFsaWQudGxzdGVzdC5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnSNfZUbiKQVt+pTHEhFiEFejOgMRJq0+U
z76Ja2F78ksYHK5kUgJVUb4ZOpHz0uENNBeCeRBQuFOGsKBmMZgIie5ZRXX7/UsM
EULAvrdcxr23/TND65iEEKt1Az66GBHdejnbYDLdgzTrH7cbFW3G3Xvsq5RNw4Yj
MNXziMj84msCx/QmNjJJZQ8UCU6wkgZ2ZTbFmfjm+k/LbDT4G52/LUC3Vb97bcKv
UQ1RwNwXpRrxtUcsBgAc6u+0StlAdYLgkVryEIX1yBrT4gvCxikwJb6q8B9IQEwP
n7Hw/zWsl2344wyXz6Pyv4yTmb6GHZauj0s5eo84hpk3R+I1NeuzAgMBAAGjIDAe
MBwGA1UdEQQVMBOCEXZhbGlkLnRsc3Rlc3QuY29tMA0GCSqGSIb3DQEBCwUAA4IB
AQBG2oIst35Wj9lk4LgYH3PIa4U33Yd1pue6QneHu+7Auobka181WJIMSHzIR1/B
60vUj7grLRUCGjbq6/jayTLTA229rifv2g9g3Vz+GP2bCyZfgWiIOYSWxUtCxBFT
GGwnjv0u1M9awG1YjzElVoZBqKAQdfx0J6NRBNgnJvQ6TzREMhA5V2sdoynOmyu5
90vKd7DlLVGg1cZx7WmGSI6ymVHYahOVz7dxH2FpxVQ3j5L7FFcxiOaffI58ccza
zfCNBbx/lvknjXwMf0wDLJQwMvqBkZ3qdDdooukicF5yIXjNFVBqJNJOvDOdo10U
VqXWhGr3Fdkg4Bm8H6ZRkvD1
-----END CERTIFICATE-----"""

ecdsaCSR = """-----BEGIN CERTIFICATE REQUEST-----
MIIBGzCBwgIBADBgMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTUQxETAPBgNVBAcM
CFRlc3RDaXR5MRUwEwYDVQQKDAxFeGFtcGxlIEluYy4xGjAYBgNVBAMMEWVjZHNh
LmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHLyc5o1XhH6+
Xt2DHBjXDubUxuxXwVzPIT5cHjZzaisl0LtX+ZaK/biA+mEMtFvYAErky2YDdV8x
wCH8ZY/y3aAAMAoGCCqGSM49BAMCA0gAMEUCICOQqKu2s9yq9yibqxvU69C0z8Q4
J8dspgDPuJbcpsTjAiEA4nhWH5rVKB3kN0h055d6ga4Dw66XlU/tgOu6Ek8GliY=
-----END CERTIFICATE REQUEST-----"""


def error():
    global ERRORS
    ERRORS += 1


def success():
    global SUCCESS
    SUCCESS += 1


def scan_test(host, data):
    params = urllib.parse.urlencode({'host':host})
    url = SCAN_URL + '?' + params
    res = {}

    try:
        req = urllib.request.urlopen(url)
        res = json.loads(req.read())
    except Exception as e:
        print("failed to connect to {}".format(host), e)
        global ERRORS
        ERRORS =+ len(data)
        return

    cert = res['certificates'][0]
    conn = res['connectionInformation']
    vuln = res['vulnerabilities']

    key_type = cert['keyType']
    server = conn['serverHeader']
    config = conn['supportedConfig']
    hbleed = vuln['heartbleed']
    ccs = vuln['ccsinjection']

    if key_type != data['exp_key_type']:
        print("Host: {} wrong key type, got {}, wanted {}".format(host, key_type, data['exp_key_type']))
        error()
    else:
        success()

    if server != data['exp_server']:
        print("Host: {} wrong server header, got {}, wanted {}".format(host, server, data['exp_server']))
        error()
    else:
        success()

    if len(config) != data['exp_protocol_count']:
        print("host: {} wrong number of protocols, got {}, wanted {}".format(host, len(config), data['exp_protocol_count']))
        error()
    else:
        success()

    for protocol, cipher in config.items():
        if len(cipher) != data['exp_cipher_count'][protocol]:
            print("Host: {} wrong number of ciphers for protocol, got {}, wanted {} for protocol {}".format(host, len(cipher), data['exp_cipher_count'][protocol], protocol))
            error()
        else:
            success()

    if hbleed != data['exp_hbleed']:
        print("Host: {} wrong heartbleed result, got {}, wanted {}".format(host, hbleed, data['exp_hbleed']))
        error()
    else:
        success()

    if ccs != data['exp_ccsinjection']:
        print("Host: {} wrong ccsinjection result, got {}, wanted {}".format(host, ccs, data['exp_ccsinjection']))
        error()
    else:
        success()


def test_cert():  
    data = bytes(rsaCert, 'utf-8')
    req = urllib.request.Request(CERT_URL, data)
    req.add_header('Content-Length', '%d' % len(rsaCert))
    req.add_header('Content-Type', 'application/octet-stream')
    res = urllib.request.urlopen(req).read()
    data = json.loads(res)

    key_type = data['keyType'] or ""
    if key_type != "RSA-2048":
        print("wrong key type, got {}, wanted {}".format(key_type, "RSA-2048"))
        error()
    else:
        success()

    sig_alg = data['signatureAlgorithm'] or ""
    if sig_alg != "SHA256-RSA":
        print("wrong signature algorithm, got {}, wanted {}".format(key_type, "SHA256-RSA"))
        error() 
    else:
        success()

    cn = data['subject']['commonName'] or ""
    if cn != "valid.tlstest.com":
        print("wrong common name, got {}, wanted {}".format(key_type, "valid.tlstest.com"))
        error() 
    else:
        success()


def test_csr():  
    data = bytes(ecdsaCSR, 'utf-8')
    req = urllib.request.Request(CSR_URL, data)
    req.add_header('Content-Length', '%d' % len(ecdsaCSR))
    req.add_header('Content-Type', 'application/octet-stream')
    res = urllib.request.urlopen(req).read()
    data = json.loads(res)

    key_type = data['keyType'] or ""
    if key_type != "ECDSA-256":
        print("wrong key type, got {}, wanted {}".format(key_type, "ECDSA-256"))
        error()
    else:
        success()

    sig_alg = data['signatureAlgorithm'] or ""
    if sig_alg != "ECDSA-SHA256":
        print("wrong signature algorithm, got {}, wanted {}".format(key_type, "ECDSA-SHA256"))
        error() 
    else:
        success()

    cn = data['subject']['commonName'] or ""
    if cn != "ecdsa.example.com":
        print("wrong common name, got {}, wanted {}".format(key_type, "ecdsa.example.com"))
        error() 
    else:
        success()
    

def main():
    print(" Starting integration tests...")

    for test, data in test_cases.items():
        scan_test(test, data)

    test_cert()

    test_csr()

    print(" Integration tests complete")

    if ERRORS > 0:
        msg = "{} of {} tests failed".format(ERRORS, (ERRORS + SUCCESS))
        sys.exit("\n " + msg)

    msg = "{} of {} tests passed".format(SUCCESS, (ERRORS + SUCCESS))
    print("\n " + msg)


if __name__ == "__main__":
  sys.exit(main())
