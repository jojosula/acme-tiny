# acme-tiny-tls-sni-challenge forked from diafygi/acme-tiny


Update acme-tiny script for tls-sni-challenge. But this script will only
prepare the challenge certificate, you still need to apply certificate
on your web server on your own.

There a one more parameter verify_type, that you can choose http, https.
Example:
```
python /path/to/acme_tiny.py --account-key /path/to/account.key --csr /path/to/domain.csr --acme-dir /var/www/challenges/  --verify_type https
```