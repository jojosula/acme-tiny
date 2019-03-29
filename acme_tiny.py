#!/usr/bin/env python
# Copyright Daniel Roesler, under MIT license, see LICENSE at github.com/diafygi/acme-tiny
import argparse, subprocess, json, os, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging
try:
    from urllib.request import urlopen, Request # Python 3
    import ssl
    context = ssl.create_default_context()
except ImportError:
    from urllib2 import urlopen, Request # Python 2
    import ssl
    context = ssl._create_unverified_context()

#DEFAULT_CA = "https://acme-staging-v02.api.letsencrypt.org"
DEFAULT_CA = "https://acme-v02.api.letsencrypt.org" # DEPRECATED! USE DEFAULT_DIRECTORY_URL INSTEAD
#DEFAULT_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"

CHALLENGE_TYPE_HTTP = 'http-01'
CHALLENGE_TYPE_TLS_SNI = 'tls-sni-01'
CHALLENGE_TYPE_TLS_SNI_V2 = 'tls-sni-02'
CHALLENGE_TYPE_TLS_ALPN = 'tls-alpn-01'
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
    http_dict['url'] = http_dict['challenge']['url']

    tls_dict = {}
    for cha in challenges:
        if cha['type'] == CHALLENGE_TYPE_TLS_SNI or cha['type'] == CHALLENGE_TYPE_TLS_SNI_V2 or cha['type'] == CHALLENGE_TYPE_TLS_ALPN:
            tls_dict['challenge'] = cha
    tls_dict['token'] = re.sub(r"[^A-Za-z0-9_\-]", "_", tls_dict['challenge']['token'])
    tls_dict['keyauthorization'] = "{0}.{1}".format(tls_dict['token'], thumbprint)
    tls_dict['url'] = tls_dict['challenge']['url']

    dns_dict = {}
    dns_dict['challenge'] = [c for c in challenges if c['type'] == CHALLENGE_TYPE_DNS][0]
    dns_dict['token'] = re.sub(r"[^A-Za-z0-9_\-]", "_", dns_dict['challenge']['token'])
    dns_dict['keyauthorization'] = "{0}.{1}".format(dns_dict['token'], thumbprint)
    dns_dict['url'] = dns_dict['challenge']['url']
    return http_dict, tls_dict, dns_dict


def get_crt(account_key, csr, acme_dir, log=LOGGER, CA=DEFAULT_CA, disable_check=False, directory_url=DEFAULT_DIRECTORY_URL, contact=None, challenge_type=CHALLENGE_TYPE_HTTP):
    directory, acct_headers, alg, jwk = None, None, None, None # global variables

    # helper functions - base64 encode for jose spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    # helper function - run external commands
    def _cmd(cmd_list, stdin=None, cmd_input=None, err_msg="Command Line Error"):
        proc = subprocess.Popen(cmd_list, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(cmd_input)
        if proc.returncode != 0:
            raise IOError("{0}\n{1}".format(err_msg, err))
        return out

    # helper function - make request and automatically parse json response
    def _do_request(url, data=None, err_msg="Error", depth=0):
        try:
            resp = urlopen(Request(url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "acme-tiny"}), context=context)
            resp_data, code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
        except IOError as e:
            resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
            code, headers = getattr(e, "code", None), {}
        try:
            resp_data = json.loads(resp_data) # try to parse json results
        except ValueError:
            pass # ignore json parsing errors
        if depth < 100 and code == 400 and resp_data['type'] == "urn:ietf:params:acme:error:badNonce":
            raise IndexError(resp_data) # allow 100 retrys for bad nonces
        if code not in [200, 201, 204]:
            raise ValueError("{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(err_msg, url, data, code, resp_data))
        return resp_data, code, headers

    # helper function - make signed requests
    def _send_signed_request(url, payload, err_msg, depth=0):
        payload64 = _b64(json.dumps(payload).encode('utf8'))
        new_nonce = _do_request(directory['newNonce'])[2]['Replay-Nonce']
        protected = {"url": url, "alg": alg, "nonce": new_nonce}
        protected.update({"jwk": jwk} if acct_headers is None else {"kid": acct_headers['Location']})
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        protected_input = "{0}.{1}".format(protected64, payload64).encode('utf8')
        out = _cmd(["openssl", "dgst", "-sha256", "-sign", account_key], stdin=subprocess.PIPE, cmd_input=protected_input, err_msg="OpenSSL Error")
        data = json.dumps({"protected": protected64, "payload": payload64, "signature": _b64(out)})
        try:
            return _do_request(url, data=data.encode('utf8'), err_msg=err_msg, depth=depth)
        except IndexError: # retry bad nonces (they raise IndexError)
            return _send_signed_request(url, payload, err_msg, depth=(depth + 1))

    # helper function - poll until complete
    def _poll_until_not(url, pending_statuses, err_msg):
        while True:
            result, _, _ = _do_request(url, err_msg=err_msg)
            if result['status'] in pending_statuses:
                time.sleep(2)
                continue
            return result

    # parse account key to get public key
    log.info("Parsing account key...")
    out = _cmd(["openssl", "rsa", "-in", account_key, "-noout", "-text"], err_msg="OpenSSL Error")
    pub_pattern = r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    pub_hex, pub_exp = re.search(pub_pattern, out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    alg = "RS256"
    jwk = {
        "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
        "kty": "RSA",
        "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
    }
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    # find domains
    log.info("Parsing CSR...")
    out = _cmd(["openssl", "req", "-in", csr, "-noout", "-text"], err_msg="Error loading {0}".format(csr))
    domains = set([])
    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", out.decode('utf8'))
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode('utf8'), re.MULTILINE|re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])
    log.info("Found domains: {0}".format(", ".join(domains)))

    # get the ACME directory of urls
    log.info("Getting directory...")
    directory_url = CA + "/directory" if CA != DEFAULT_CA else directory_url # backwards compatibility with deprecated CA kwarg
    directory, _, _ = _do_request(directory_url, err_msg="Error getting directory")
    log.info("Directory found!")

    # create account, update contact details (if any), and set the global key identifier
    log.info("Registering account...")
    reg_payload = {"termsOfServiceAgreed": True}
    account, code, acct_headers = _send_signed_request(directory['newAccount'], reg_payload, "Error registering")
    log.info("Registered!" if code == 201 else "Already registered!")
    if contact is not None:
        account, _, _ = _send_signed_request(acct_headers['Location'], {"contact": contact}, "Error updating contact details")
        log.info("Updated contact details:\n{0}".format("\n".join(account['contact'])))

    # create a new order
    log.info("Creating new order...")
    order_payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
    order, _, order_headers = _send_signed_request(directory['newOrder'], order_payload, "Error creating new order")
    log.info("Order created!")

    # get the authorizations that need to be completed
    for auth_url in order['authorizations']:
        authorization, _, _ = _do_request(auth_url, err_msg="Error getting challenges")
        domain = authorization['identifier']['value']
        log.info("Verifying {0}...".format(domain))

        # parse challenges
        http_challenge_dict, tls_challenge_dict, dns_challenge_dict = parse_challenges(
            authorization['challenges'], thumbprint)

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
                assert(disable_check or _do_request(wellknown_url)[0] == http_challenge_dict['keyauthorization'])
            except (AssertionError, ValueError) as e:
                os.remove(wellknown_path)
                raise ValueError("Wrote file to {0}, but couldn't download {1}".format(
                    wellknown_path, wellknown_url))

        # say the challenge is done
        _send_signed_request(challenge_dict['url'], {}, "Error submitting challenges: {0}".format(domain))
        authorization = _poll_until_not(auth_url, ["pending"], "Error checking challenge status for {0}".format(domain))
        if authorization['status'] != "valid":
            raise ValueError("Challenge did not pass for {0}: {1}".format(domain, authorization))
        log.info("{0} verified!".format(domain))

        # remove file
        if wellknown_path:
            os.remove(wellknown_path)

    # finalize the order with the csr
    log.info("Signing certificate...")
    csr_der = _cmd(["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error")
    _send_signed_request(order['finalize'], {"csr": _b64(csr_der)}, "Error finalizing order")

    # poll the order to monitor when it's done
    order = _poll_until_not(order_headers['Location'], ["pending", "processing"], "Error checking order status")
    if order['status'] != "valid":
        raise ValueError("Order failed: {0}".format(order))

    # download the certificate
    certificate_pem, _, _ = _do_request(order['certificate'], err_msg="Certificate download failed")
    log.info("Certificate signed!")
    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(certificate_pem).decode('utf8'), 64)))

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate from Let's Encrypt using
            the ACME protocol. It will need to be run on your server and have access to your private
            account key, so PLEASE READ THROUGH IT! It's only ~200 lines, so it won't take long.

            ===Example Usage===
            python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > signed_chain.crt
            ===================

            ===Example Crontab Renewal (once per month)===
            0 0 1 * * python /path/to/acme_tiny.py --account-key /path/to/account.key --csr /path/to/domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > /path/to/signed_chain.crt 2>> /var/log/acme_tiny.log
            ==============================================
            """)
    )
    parser.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
    parser.add_argument("--csr", required=True, help="path to your certificate signing request")
    parser.add_argument("--acme-dir", required=True, help="path to the .well-known/acme-challenge/ directory")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("--disable-check", default=False, action="store_true", help="disable checking if the challenge file is hosted correctly before telling the CA")
    parser.add_argument("--directory-url", default=DEFAULT_DIRECTORY_URL, help="certificate authority directory url, default is Let's Encrypt")
    parser.add_argument("--ca", default=DEFAULT_CA, help="DEPRECATED! USE --directory-url INSTEAD!")
    parser.add_argument("--contact", metavar="CONTACT", default=None, nargs="*", help="Contact details (e.g. mailto:aaa@bbb.com) for your account-key")
    parser.add_argument("--verify_type", default="http", help="challenge type for verify domain. default is http")

    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or LOGGER.level)

    if args.verify_type == "https":
        challenge_type = CHALLENGE_TYPE_TLS_SNI
    elif args.verify_type == "dns":
        challenge_type = CHALLENGE_TYPE_DNS
    else:
        challenge_type = CHALLENGE_TYPE_HTTP

    signed_crt = get_crt(args.account_key, args.csr, args.acme_dir, log=LOGGER, CA=args.ca, disable_check=args.disable_check, directory_url=args.directory_url, contact=args.contact, challenge_type=challenge_type)
    sys.stdout.write(signed_crt)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
