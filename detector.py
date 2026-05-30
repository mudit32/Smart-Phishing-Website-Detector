# Import required libraries for domain parsing, SSL validation, WHOIS lookups, and web content fetching
import requests
import datetime
import whois
import ssl
import socket
from urllib.parse import urlparse
from OpenSSL import crypto

class PhishingDetector:
    def __init__(self, url):
        self.url = url
        self.domain = urlparse(url).netloc   # Extract domain name from URL
        self.scheme = urlparse(url).scheme   # Extract protocol (http/https)

    # Check the total length of the URL — longer URLs are often suspicious
    def get_url_length(self):
        return len(self.url)

    # Check whether the website has a valid SSL certificate
    def check_ssl_certificate(self):
        if self.scheme != "https":
            return None  # No SSL used (HTTP)
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=self.domain) as conn:
                conn.settimeout(5)
                conn.connect((self.domain, 443))  # Connect to domain on HTTPS port
                cert = conn.getpeercert()         # Try to retrieve SSL certificate
                return bool(cert)
        except Exception:
            return False  # Invalid or missing certificate

    # Calculate how old the domain is in days — newer domains are more suspicious
    def get_domain_age(self):
        try:
            domain_info = whois.whois(self.domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):  # Handle multiple creation dates
                creation_date = creation_date[0]
            if not creation_date:
                return -1
            current_date = datetime.datetime.now()
            return (current_date - creation_date).days
        except Exception:
            return -1  # WHOIS lookup failed

    # Check for suspicious phishing-related keywords in the HTML content of the site
    def check_suspicious_content(self):
        try:
            response = requests.get(self.url, timeout=5)
            if response.status_code == 200:
                keywords = ['login', 'verify', 'account', 'password', 'bank']
                content = response.text.lower()
                return sum(1 for keyword in keywords if keyword in content)
        except:
            return -1  # If page can't be reached or timed out
        return -1

    # Suggest the legitimate website if a known brand is being impersonated
    def get_legitimate_site(self):
        brand_domains = {
            'paypal': 'https://www.paypal.com',
            'amazon': 'https://www.amazon.com',
            'bankofamerica': 'https://www.bankofamerica.com',
            'microsoft': 'https://www.microsoft.com',
            'apple': 'https://www.apple.com'
        }
        for brand in brand_domains:
            if brand in self.domain.lower() and not self.domain.endswith(brand_domains[brand].replace("https://", "")):
                return brand_domains[brand]  # Return actual site if brand name is used in a fake domain
        return None

    # Perform rule-based phishing detection
    def detect_phishing(self):
        url_length = self.get_url_length()
        domain_age = self.get_domain_age()
        suspicious_content = self.check_suspicious_content()
        ssl_status = self.check_ssl_certificate()

        result = ""
        fake_brand_targets = ['paypal', 'amazon', 'bankofamerica', 'microsoft', 'apple']
        real_domains = {
            'paypal': 'paypal.com',
            'amazon': 'amazon.com',
            'bankofamerica': 'bankofamerica.com',
            'microsoft': 'microsoft.com',
            'apple': 'apple.com'
        }

        # Check if domain includes a fake brand name
        for brand in fake_brand_targets:
            if brand in self.domain.lower():
                if not self.domain.endswith(real_domains[brand]):
                    result = "Phishing (Fake brand domain)"
                    break

        # Rule-based scoring system
        score = 0
        if url_length > 75:
            score += 1
        if domain_age != -1 and domain_age < 30:
            score += 1
        if suspicious_content > 2:
            score += 1

        # Final decision based on rule results
        if not result and score >= 2:
            result = "Phishing"
        if not result:
            result = "Not Phishing"

        # Add SSL warnings if needed
        if ssl_status is None:
            result += " (Warning: No SSL - site not secure)"
        elif ssl_status is False:
            result += " (Warning: Invalid SSL)"

        return result

