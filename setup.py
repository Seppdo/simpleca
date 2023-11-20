import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

ca_key_passphrase = b'supersecretpassphrase'


def create_ca():
    ca_dir = Path('ca')
    ca_dir.mkdir(parents=True, exist_ok=True)

    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    with open(ca_dir.joinpath('ca.key'), 'wb') as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(ca_key_passphrase)
        ))

    ca_subject = ca_issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sachsen-Anhalt"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Wernigerode"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Hochschule Harz"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Netlab"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")
    ])

    ca_crt = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        ca_issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("ca.netlab.hs-harz.de")]),
        critical=False
    ).add_extension(
        x509.BasicConstraints(True, 2),
        critical=False
    ).add_extension(
        x509.KeyUsage(
            False,
            False,
            False,
            False,
            False,
            True,
            True,
            False,
            False
        ),
        critical=False
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
        critical=False
    ).sign(ca_key, hashes.SHA256())

    with open(ca_dir.joinpath('ca.crt'), 'wb') as f:
        f.write(ca_crt.public_bytes(serialization.Encoding.PEM))

    intermediate_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    with open(ca_dir.joinpath('intermediate.key'), 'wb') as f:
        f.write(intermediate_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(ca_key_passphrase)
        ))

    intermediate_subject = intermediate_issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sachsen-Anhalt"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Wernigerode"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Hochschule Harz"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Netlab"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")
    ])

    intermediate_crt = x509.CertificateBuilder().subject_name(
        intermediate_subject
    ).issuer_name(
        ca_issuer
    ).public_key(
        intermediate_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("intermediate-ca.netlab.hs-harz.de")]),
        critical=False
    ).add_extension(
        x509.BasicConstraints(True, 1),
        critical=False
    ).add_extension(
        x509.KeyUsage(
            False,
            False,
            False,
            False,
            False,
            True,
            True,
            False,
            False
        ),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()),
        critical=False
    ).sign(ca_key, hashes.SHA256())

    with open(ca_dir.joinpath('intermediate.crt'), 'wb') as f:
        f.write(intermediate_crt.public_bytes(serialization.Encoding.PEM))

    certs_dir = Path('certs')
    certs_dir.mkdir(parents=True, exist_ok=True)

    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    with open(certs_dir.joinpath('server.key'), 'wb') as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(ca_key_passphrase)
        ))

    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sachsen-Anhalt"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Wernigerode"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Hochschule Harz"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Netlab"),
        x509.NameAttribute(NameOID.COMMON_NAME, "server.netlab.hs-harz.de")
    ])

    server_crt = x509.CertificateBuilder().subject_name(
        server_subject
    ).issuer_name(
        intermediate_issuer
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("server.netlab.hs-harz.de")]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(False, None),
        critical=False
    ).add_extension(
        x509.KeyUsage(
            True,
            True,
            True,
            True,
            True,
            False,
            False,
            False,
            False
        ),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()),
        critical=False
    ).sign(intermediate_key, hashes.SHA256())

    with open(certs_dir.joinpath('server.crt'), 'wb') as f:
        f.write(server_crt.public_bytes(serialization.Encoding.PEM))

    with open(certs_dir.joinpath('server.chain.crt'), 'wb') as f:
        f.write(server_crt.public_bytes(serialization.Encoding.PEM))
        f.write(intermediate_crt.public_bytes(serialization.Encoding.PEM))
        f.write(server_crt.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    create_ca()
