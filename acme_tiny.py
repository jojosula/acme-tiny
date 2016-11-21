#!/usr/bin/env python
import argparse, subprocess, json, os, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging
try:
    from urllib.request import urlopen # Python 3
except ImportError:
    from urllib2 import urlopen # Python 2

#DEFAULT_CA = "https://acme-staging.api.letsencrypt.org"
DEFAULT_CA = "https://acme-v01.api.letsencrypt.org"

CHALLENGE_TYPE_HTTP = 'http-01'
CHALLENGE_TYPE_TLS_SNI = 'tls-sni-01'
CHALLENGE_TYPE_TLS_SNI_V2 = 'tls-sni-02'
CHALLENGE_TYPE_DNS = 'dns-01'

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def create_self_signed_cert_windows(san_a, san_b):
    path = os.getcwd()
    # windows style
    origin_openssl_cnf = '{0}\\tests\\openssl.cnf'
    self_csr_cnf = '{0}\\tmp\\csr.cnf'
    self_csr = '{0}\\tmp\\self_csr'
    self_key = '{0}\\tmp\\self_key'
    self_cert = '{0}\\tmp\\self_cert'
    cp_cmd = ('copy ' + origin_openssl_cnf + ' ' + self_csr_cnf + ' /y').format(path)
    os.system(cp_cmd)

    echo_cmd = ('echo [alt_names] >> ' + self_csr_cnf).format(path)
    os.system(echo_cmd)
    if san_b:
        echo_cmd = ('echo DNS.1={1},DNS.2={2} >> ' + self_csr_cnf).format(path, san_a, san_b)
    else:
        echo_cmd = ('echo DNS.1={1} >> ' + self_csr_cnf).format(path, san_a)
    os.system(echo_cmd)
    csr_cmd = ('openssl req -new -newkey rsa:2048 -nodes -sha256 -keyout ' + self_key +
        ' -out ' + self_csr + ' -subj "/CN=dummy" -config ' + self_csr_cnf).format(path)
    print csr_cmd
    os.system(csr_cmd)
    cert_cmd = ('openssl x509 -req -days 7 -extensions v3_req -extfile ' + self_csr_cnf +
        ' -in ' + self_csr + ' -signkey ' + self_key + ' -out ' + self_cert).format(path)
    print cert_cmd
    os.system(cert_cmd)


def create_self_signed_cert_linux(san_a, san_b):
    path = os.getcwd()
    # linux style
    origin_openssl_cnf = '{0}/tests/openssl.cnf'
    self_csr_cnf = '{0}/tmp/csr.cnf'
    self_csr = '{0}/tmp/self_csr'
    self_key = '{0}/tmp/self_key'
    self_cert = '{0}/tmp/self_cert'
    cp_cmd = ('cp ' + origin_openssl_cnf + ' ' + self_csr_cnf).format(path)
    result = os.system(cp_cmd)
    if san_b:
        echo_cmd = ('echo -e \"[alt_names]\nDNS.1={1},DNS.2={2}\" >> ' + self_csr_cnf).format(path, san_a, san_b)
    else:
        echo_cmd = ('echo -e \"[alt_names]\nDNS.1={1}\" >> ' + self_csr_cnf).format(path, san_a)
    print echo_cmd
    os.system(echo_cmd)
    csr_cmd = ('openssl req -new -newkey rsa:2048 -nodes -sha256 -keyout ' + self_key +
        ' -out ' + self_csr + ' -subj "/CN=dummy" -config ' + self_csr_cnf).format(path)
    print csr_cmd
    os.system(csr_cmd)
    cert_cmd = ('openssl x509 -req -days 7 -extensions v3_req -extfile ' + self_csr_cnf +
        ' -in ' + self_csr + ' -signkey ' + self_key + ' -out ' + self_cert).format(path)
    print cert_cmd
    os.system(cert_cmd)


# replace the function by your os
create_self_signed_cert = create_self_signed_cert_windows


def prepare_tls_sni_challenge(tls_dict):
    hex_token = hashlib.sha256(
        tls_dict['token'].encode('utf8')).hexdigest().lower().encode()
    hex_key = hashlib.sha256(
        tls_dict['keyauthorization'].encode('utf8')).hexdigest().lower().encode()

    # domain is too big to fit into CN, hence fit into subjectAltName
    if tls_dict['challenge']['type'] == CHALLENGE_TYPE_TLS_SNI:
        # tls-sni-01
        san_a = b'{0}.{1}.acme.invalid'.format(hex_key[:32], hex_key[32:])
        san_b = None
    else:
        # tls-sni-02
        san_a = "{0}.{1}.token.acme.invalid".format(hex_token[:32], hex_token[32:])
        san_b = b'{0}.{1}.ka.acme.invalid'.format(hex_key[:32], hex_key[32:])
    create_self_signed_cert(san_a, san_b)


def prepare_dns_challenge(domain_name, dns_dict):
    # make the challenge file
    host = domain_name.split('.')[0]
    dns_txt_name = "{0}.{1}".format('_acme-challenge', host)
    key_digest = hashlib.sha256(
        dns_dict['keyauthorization'].encode('utf8')).digest()
    content = base64.urlsafe_b64encode(key_digest).decode('utf8').replace("=", "")


def parse_challenges(challenges, thumbprint):
    http_dict = {}
    http_dict['challenge'] = [c for c in challenges if c['type'] == CHALLENGE_TYPE_HTTP][0]
    http_dict['token'] = re.sub(r"[^A-Za-z0-9_\-]", "_", http_dict['challenge']['token'])
    http_dict['keyauthorization'] = "{0}.{1}".format(http_dict['token'], thumbprint)

    tls_dict = {}
    for cha in challenges:
        if cha['type'] == CHALLENGE_TYPE_TLS_SNI or cha['type'] == CHALLENGE_TYPE_TLS_SNI_V2:
            tls_dict['challenge'] = cha
    tls_dict['token'] = re.sub(r"[^A-Za-z0-9_\-]", "_", tls_dict['challenge']['token'])
    tls_dict['keyauthorization'] = "{0}.{1}".format(tls_dict['token'], thumbprint)

    dns_dict = {}
    dns_dict['challenge'] = [c for c in challenges if c['type'] == CHALLENGE_TYPE_DNS][0]
    dns_dict['token'] = re.sub(r"[^A-Za-z0-9_\-]", "_", dns_dict['challenge']['token'])
    dns_dict['keyauthorization'] = "{0}.{1}".format(dns_dict['token'], thumbprint)
    return http_dict, tls_dict, dns_dict


def get_crt(account_key, csr, acme_dir, log=LOGGER, CA=DEFAULT_CA, challenge_type=CHALLENGE_TYPE_HTTP):
    # helper function base64 encode for jose spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    # parse account key to get public key
    log.info("Parsing account key...")
    proc = subprocess.Popen(["openssl", "rsa", "-in", account_key, "-noout", "-text"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    pub_hex, pub_exp = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    header = {
        "alg": "RS256",
        "jwk": {
            "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
    }
    accountkey_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    # helper function make signed requests
    def _send_signed_request(url, payload):
        payload64 = _b64(json.dumps(payload).encode('utf8'))
        protected = copy.deepcopy(header)
        protected["nonce"] = urlopen(CA + "/directory").headers['Replay-Nonce']
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        proc = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", account_key],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate("{0}.{1}".format(protected64, payload64).encode('utf8'))
        if proc.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        data = json.dumps({
            "header": header, "protected": protected64,
            "payload": payload64, "signature": _b64(out),
        })
        try:
            resp = urlopen(url, data.encode('utf8'))
            return resp.getcode(), resp.read()
        except IOError as e:
            return getattr(e, "code", None), getattr(e, "read", e.__str__)()

    # find domains
    log.info("Parsing CSR...")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-noout", "-text"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("Error loading {0}: {1}".format(csr, err))
    domains = set([])
    common_name = re.search(r"Subject:.*? CN=([^\s,;/]+)", out.decode('utf8'))
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode('utf8'), re.MULTILINE|re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])

    # get the certificate domains and expiration
    log.info("Registering account...")
    code, result = _send_signed_request(CA + "/acme/new-reg", {
        "resource": "new-reg",
        "agreement": "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf",
    })
    if code == 201:
        log.info("Registered!")
    elif code == 409:
        log.info("Already registered!")
    else:
        raise ValueError("Error registering: {0} {1}".format(code, result))

    # verify each domain
    for domain in domains:
        log.info("Verifying {0}...".format(domain))

        # get new challenge
        code, result = _send_signed_request(CA + "/acme/new-authz", {
            "resource": "new-authz",
            "identifier": {"type": "dns", "value": domain},
        })
        if code != 201:
            raise ValueError("Error requesting challenges: {0} {1}".format(code, result))

        # parse challenges
        http_challenge_dict, tls_challenge_dict, dns_challenge_dict = parse_challenges(
            json.loads(result.decode('utf8'))['challenges'], thumbprint)

        wellknown_path = ''
        # choose challenge for verify
        if challenge_type == CHALLENGE_TYPE_TLS_SNI:
            challenge_dict = tls_challenge_dict
            # prepare tls-sni challenge
            prepare_tls_sni_challenge(tls_challenge_dict)
            # FIXME: need to apply certificate on your own
        elif challenge_type == CHALLENGE_TYPE_DNS:
            challenge_dict = dns_challenge_dict
            # prepare DNS challenge
            # FIXME: need to add TXT record on your own
        else:
            challenge_dict = http_challenge_dict
            # prepare http challenge
            wellknown_path = os.path.join(acme_dir, http_challenge_dict['token'])
            with open(wellknown_path, "w") as wellknown_file:
                wellknown_file.write(http_challenge_dict['keyauthorization'])

            # check that the file is in place
            wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, http_challenge_dict['token'])
            try:
                resp = urlopen(wellknown_url)
                resp_data = resp.read().decode('utf8').strip()
                assert resp_data == http_challenge_dict['keyauthorization']
            except (IOError, AssertionError):
                os.remove(wellknown_path)
                raise ValueError("Wrote file to {0}, but couldn't download {1}".format(
                    wellknown_path, wellknown_url))

        # notify challenge are met
        code, result = _send_signed_request(challenge_dict['challenge']['uri'], {
            "resource": "challenge",
            "keyAuthorization": challenge_dict['keyauthorization'],
        })
        if code != 202:
            raise ValueError("Error triggering challenge: {0} {1}".format(code, result))

        # wait for challenge to be verified
        while True:
            try:
                resp = urlopen(challenge_dict['challenge']['uri'])
                challenge_status = json.loads(resp.read().decode('utf8'))
            except IOError as e:
                raise ValueError("Error checking challenge: {0} {1}".format(
                    e.code, json.loads(e.read().decode('utf8'))))
            if challenge_status['status'] == "pending":
                time.sleep(2)
            elif challenge_status['status'] == "valid":
                log.info("{0} verified!".format(domain))
                break
            else:
                raise ValueError("{0} challenge did not pass: {1}".format(
                    domain, challenge_status))

        # remove file
        if wellknown_path:
            os.remove(wellknown_path)

    # get the new certificate
    log.info("Signing certificate...")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-outform", "DER"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    csr_der, err = proc.communicate()
    code, result = _send_signed_request(CA + "/acme/new-cert", {
        "resource": "new-cert",
        "csr": _b64(csr_der),
    })
    if code != 201:
        raise ValueError("Error signing certificate: {0} {1}".format(code, result))

    # return signed certificate!
    log.info("Certificate signed!")
    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(result).decode('utf8'), 64)))

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate from
            Let's Encrypt using the ACME protocol. It will need to be run on your server
            and have access to your private account key, so PLEASE READ THROUGH IT! It's
            only ~200 lines, so it won't take long.

            ===Example Usage===
            python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > signed.crt
            ===================

            ===Example Crontab Renewal (once per month)===
            0 0 1 * * python /path/to/acme_tiny.py --account-key /path/to/account.key --csr /path/to/domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > /path/to/signed.crt 2>> /var/log/acme_tiny.log
            ==============================================
            """)
    )
    parser.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
    parser.add_argument("--csr", required=True, help="path to your certificate signing request")
    parser.add_argument("--acme-dir", required=True, help="path to the .well-known/acme-challenge/ directory")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("--ca", default=DEFAULT_CA, help="certificate authority, default is Let's Encrypt")
    parser.add_argument("--verify_type", default="http", help="challenge type for verify domain. default is http")

    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or LOGGER.level)

    if args.verify_type == "https":
        challenge_type = CHALLENGE_TYPE_TLS_SNI
    elif args.verify_type == "dns":
        challenge_type = CHALLENGE_TYPE_DNS
    else:
        challenge_type = CHALLENGE_TYPE_HTTP

    signed_crt = get_crt(args.account_key, args.csr, args.acme_dir, log=LOGGER, CA=args.ca, challenge_type=challenge_type)
    sys.stdout.write(signed_crt)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
