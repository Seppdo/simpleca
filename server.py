import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from sanic import Sanic, text, HTTPResponse, redirect, file
from cryptography import x509
from sanic_ext import render

from sign import sign

app = Sanic("LaborCA")


@app.get("/")
@app.ext.template("index.html")
async def index(request):
    return {}


@app.get("/csr/upload")
@app.ext.template("csr-upload.html")
async def csr_upload(request):
    return {}


@app.post("/csr/check")
@app.ext.template("csr-check.html")
async def csr_check(request) -> HTTPResponse:
    csr = request.files.get("csr")
    print(csr.type)

    if csr is None:
        return text("No CSR")

    try:
        x509_csr = x509.load_pem_x509_csr(csr.body)
    except:
        return text("Invalid CSR")

    x509_csr_bytes = x509_csr.public_bytes(encoding=serialization.Encoding.PEM)
    x509_csr_check = {
        'subject': x509_csr.subject.rfc4514_string(),
        'csr': x509_csr_bytes.decode('utf-8'),
        'public_key': x509_csr.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8'),
    }
    try:
        x509_csr_check['SAN'] = ' '.join([f"{type(san).__name__}: {san.value}" for san in x509_csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value])
    except x509.ExtensionNotFound:
        x509_csr_check['SAN'] = 'No SAN'

    # save csr to file
    csr_path = Path('csr')
    csr_path.mkdir(parents=True, exist_ok=True)
    csr_name = x509_csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    csr_name += '-' + hashlib.sha256(x509_csr_bytes).hexdigest()[:8]

    with csr_path.joinpath(csr_name + '.csr').open('wb') as f:
        f.write(x509_csr_bytes)

    response = await render(context={'csr': x509_csr_check})
    response.add_cookie('process', csr_name)
    return response


@app.get("/csr/sign")
async def csr_sign(request) -> HTTPResponse:
    process = request.cookies.get("process")
    if process is None:
        return text("No process", status=404)

    if sign(process):
        return redirect("/download", status=303)

    return text('Could not sign CSR', status=500)


@app.get("/download")
@app.ext.template("download.html")
async def download(request):
    process = request.cookies.get("process")
    if process is None:
        return text("No process", status=404)

    cert_dir = Path('certs')

    return {
        'cert_file': cert_dir.joinpath(process + '.crt'),
        'cert_chain_file': cert_dir.joinpath(process + '.chain.crt'),
        'cert_full_chain_file': cert_dir.joinpath(process + '.full-chain.crt')
    }


@app.get("/download/<filepath:path>")
async def download_file(request, filepath):
    # check if file exists
    file_obj = Path(filepath)
    if not file_obj.exists():
        return text("File not found", status=404)

    return await file(file_obj)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80)
