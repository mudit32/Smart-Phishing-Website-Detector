import ssl
import socket
from OpenSSL import crypto

def get_ssl_certificate(domain):
    """ Extract SSL certificate information. """
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        issuer = x509.get_issuer()
        expiry_date = x509.get_notAfter().decode('utf-8')
        return {
            "issuer": issuer.CN,
            "expiry_date": expiry_date
        }
    except Exception:
        return {"error": "SSL Certificate not available"}
