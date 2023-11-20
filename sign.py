import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

ca_key_passphrase = b'supersecretpassphrase'


def sign(process: str) -> bool:
    # Load CSR
    csr_path = Path('csr')
    try:
        csr = csr_path.joinpath(process + '.csr').read_bytes()
        x509_csr = x509.load_pem_x509_csr(csr)
    except FileNotFoundError:
        return False

    # Load CA
    ca_path = Path('ca')
    intermediate_key = load_pem_private_key(ca_path.joinpath('intermediate.key').read_bytes(), ca_key_passphrase)
    intermediate_crt = x509.load_pem_x509_certificate(ca_path.joinpath('intermediate.crt').read_bytes())
    ca_crt = x509.load_pem_x509_certificate(ca_path.joinpath('ca.crt').read_bytes())

    intermediate_issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sachsen-Anhalt"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Wernigerode"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Hochschule Harz"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Netlab"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Netlab Intermediate CA")
    ])

    certs_dir = Path('certs')
    certs_dir.mkdir(parents=True, exist_ok=True)

    server_crt_builder = (x509.CertificateBuilder().subject_name(
        x509_csr.subject
    ).issuer_name(
        intermediate_issuer
    ).public_key(
        x509_csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(False, None),
        critical=True
    ).add_extension(
        x509.KeyUsage(
            True,
            True,
            False,
            True,
            True,
            False,
            False,
            False,
            False
        ),
        critical=True
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()),
        critical=False
    ))

    try:
        server_crt_builder.add_extension(
            x509_csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
            critical=True
        )
    except x509.ExtensionNotFound:
        pass

    server_crt = server_crt_builder.sign(intermediate_key, hashes.SHA256())

    # Write server certificate and chains
    with open(certs_dir.joinpath(process + '.crt'), 'wb') as f:
        f.write(server_crt.public_bytes(serialization.Encoding.PEM))

    with open(certs_dir.joinpath(process + '.chain.crt'), 'wb') as f:
        f.write(server_crt.public_bytes(serialization.Encoding.PEM))
        f.write(intermediate_crt.public_bytes(serialization.Encoding.PEM))

    with open(certs_dir.joinpath(process + '.full-chain.crt'), 'wb') as f:
        f.write(server_crt.public_bytes(serialization.Encoding.PEM))
        f.write(intermediate_crt.public_bytes(serialization.Encoding.PEM))
        f.write(ca_crt.public_bytes(serialization.Encoding.PEM))

    return True
