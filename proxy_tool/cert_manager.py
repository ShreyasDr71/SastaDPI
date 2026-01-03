
import os
import datetime
import ipaddress
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

class CertManager:
    def __init__(self, cert_dir="certs"):
        self.cert_dir = cert_dir
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)
        
        self.ca_key_path = os.path.join(cert_dir, "ca.key")
        self.ca_cert_path = os.path.join(cert_dir, "ca.crt")
        self.cert_cache = {}

        self.load_or_create_ca()

    def load_or_create_ca(self):
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            with open(self.ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
        else:
            self.generate_ca()

    def generate_ca(self):
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"Antigravity Proxy CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Antigravity"),
        ])

        self.ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(self.ca_key, hashes.SHA256())

        with open(self.ca_key_path, "wb") as f:
            f.write(self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        
        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def get_certificate(self, domain):
        if domain in self.cert_cache:
            return self.cert_cache[domain]

        # Generate private key for the domain
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])

        # Create certificate request
        # We skip CSR object and build cert directly since we have the CA key

        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        )
        
        # Add SubjectAltName
        try:
            # Check if domain is an IP address
            ip = ipaddress.ip_address(domain)
            san_type = x509.IPAddress(ip)
        except ValueError:
            san_type = x509.DNSName(domain)
            
        builder = builder.add_extension(
            x509.SubjectAlternativeName([san_type]),
            critical=False,
        )

        cert = builder.sign(self.ca_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        
        cert_path = os.path.join(self.cert_dir, f"{domain}.crt")
        key_path = os.path.join(self.cert_dir, f"{domain}.key")
        
        with open(cert_path, "wb") as f:
            f.write(cert_pem)
        with open(key_path, "wb") as f:
            f.write(key_pem)

        self.cert_cache[domain] = (cert_path, key_path)
        return cert_path, key_path
