#!/usr/bin/env python

import json
import os
import subprocess
import sys
import time
import urllib

import urllib2

APP_HOST = "http://localhost:8080/api/v1"
SCAN_URL = APP_HOST + "/scan"
CSR_URL = APP_HOST + "/parse/csr"
CERT_URL = APP_HOST + "/parse/certificate"

ERRORS = 0
SUCCESS = 0

test_cases = {
    "nginx_vuln": {
        "exp_key_type": "RSA-2048",
        "exp_server": "nginx/1.2.9",
        "exp_config_len": 5,
        "exp_hbleed": "yes",
    },
    "postfix_vuln:25": {
        "exp_key_type": "RSA-2048",
        "exp_server": "220 mail.example.com ESMTP Postfix (Ubuntu)",
        "exp_config_len": 4,
        "exp_hbleed": "no",
    },
}

rsaCert = """-----BEGIN CERTIFICATE-----
MIIDVDCCAjwCAQEwDQYJKoZIhvcNAQELBQAwbTEZMBcGA1UEAwwQU2VsZi1TaWdu
ZWQgUm9vdDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAlVUMQ0wCwYDVQQHDARMZWhp
MRkwFwYDVQQKDBBTZWxmLVNpZ25lZCBJbmMuMQwwCgYDVQQLDANTUkUwHhcNMjAw
MTMwMDM1MTQ2WhcNMjAwMjA2MDM1MTQ2WjBzMQswCQYDVQQGEwJVUzELMAkGA1UE
CAwCVVQxDTALBgNVBAcMBExlaGkxGTAXBgNVBAoMEFNlbGYtU2lnbmVkIEluYy4x
DDAKBgNVBAsMA1NSRTEfMB0GA1UEAwwWdmFsaWQuZGlnaWNlcnR0ZXN0LmNvbTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALnOOz9wzN3n+XFHehscOVcK
BlJOk46i3ywy45Dhze9YPp49QSqJ0L26eHLDlJy2217v/EhmIFppDIKd7Zio0pb2
tQ4Wr4FxT4/3vVrP8Pdl+/C9GJW8bMIgqFtMGoFyg+5m4BhpMJ75BJA8Y7tNHdyx
tdrr/6phDsZU81UMAPSr/hSK6WYKmfX4wROJvcB5pR63FraJ0YWVrQXcvpezwZft
Rbf8jNykNpo3BUbT3A+TRHircYn2WXeLRAt1/DtbDLqcHcSBu0EiKO+ZT/OsDue6
SZQENhTwIa/DNCWrY7ROlxC6Mc/HX71UPaC8UC12OLPg2Ud8t+tI1hgYPo1zaZEC
AwEAATANBgkqhkiG9w0BAQsFAAOCAQEALsdOu0g52hbrfDXDmt9+c7Wf3MJenfWm
onWmkGvmwOeFXRLdDKBsxvExTgT6cZk/n/hBPxGKiSk451mNNvpu7xvepgfbV4zu
kbTD/3S+SFtdr6FHa6TaN2xzz5c4VwSGpcrm52q5Y9SOsoMBkERBZlW4n/KgyIXF
l9YHhUnZqdzBFR5HpIjlTRjH/t4mr1b2N5VtX47+q4K7VdRRwIo92eiJjOmtKUmu
xthBi35d/5gx702uQf6a6qIgOKF4sPcG64F73Ba7bnE2XRlQsPGF+ZM1gNx1sZAK
zzYcXCDqfJ+n5tvxFsVKvK4EMfZqD3T1GhajZ7DsVs786cNo9H8wwQ==
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
    params = urllib.urlencode({'host':host})
    url = SCAN_URL + '?' + params
    res = {}

    try:
        req = urllib2.urlopen(url)
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

    if key_type != data['exp_key_type']:
        print("wrong key type, got {}, wanted {}".format(key_type, data['exp_key_type']))
        error()
    else:
        success()

    if server != data['exp_server']:
        print("wrong server header, got {}, wanted {}".format(server, data['exp_server']))
        error()
    else:
        success()

    if len(config) != data['exp_config_len']:
        print("wrong number of protocols, got {}, wanted {}".format(len(config), data['exp_config_len']))
        error()
    else:
        success()

    if hbleed != data['exp_hbleed']:
        print("wrong heartbleed result, got {}, wanted {}".format(hbleed, data['exp_hbleed']))
        error()
    else:
        success()


def test_cert():  
    req = urllib2.Request(CERT_URL, rsaCert)
    req.add_header('Content-Length', '%d' % len(rsaCert))
    req.add_header('Content-Type', 'application/octet-stream')
    res = urllib2.urlopen(req).read()
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
    req = urllib2.Request(CSR_URL, ecdsaCSR)
    req.add_header('Content-Length', '%d' % len(ecdsaCSR))
    req.add_header('Content-Type', 'application/octet-stream')
    res = urllib2.urlopen(req).read()
    data = json.loads(res)

    key_type = data['keyType'] or ""
    if key_type != "ECDSA-253":
        print("wrong key type, got {}, wanted {}".format(key_type, "ECDSA-253"))
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
    # setup for acceptance tests
    subprocess.call(["docker-compose", "-f", "acceptance.yml", "pull"], stdout=open(os.devnull, 'wb'))
    subprocess.call(["docker-compose", "-f", "acceptance.yml", "up", "-d"])

    # sleep for containers to come up
    time.sleep(20)

    for test, data in test_cases.items():
        scan_test(test, data)

    test_csr()

    test_cert()

    subprocess.call(["docker-compose", "-f", "acceptance.yml", "down"], stdout=open(os.devnull, 'wb'))

    if ERRORS > 0:
        msg = "{} of {} tests failed".format(ERRORS, (ERRORS + SUCCESS))
        sys.exit("\n " + msg)

    msg = "{} of {} tests passed".format(SUCCESS, (ERRORS + SUCCESS))
    print("\n " + msg)


if __name__ == "__main__":
  sys.exit(main())
