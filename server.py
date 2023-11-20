from cryptography.hazmat.primitives import serialization
from sanic import Sanic, text, HTTPResponse
from cryptography import x509
from sanic_ext import render

app = Sanic("LaborCA")


@app.get("/")
async def index(request):
    return text("Labor CA")


@app.get("/csr/upload")
@app.ext.template("csr-upload.html")
async def csr_upload(request):
    return {}


@app.post("/csr/check")
@app.ext.template("csr-check.html")
async def csr_check(request) -> HTTPResponse:
    csr = request.files.get("csr")

    if csr is None:
        return text("No CSR")
    if csr.type != 'application/pkcs10':
        return text("Invalid CSR")

    x509_csr = x509.load_pem_x509_csr(csr.body)
    x509_csr_check = {'subject': x509_csr.subject.rfc4514_string(), 'csr': x509_csr.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')}
    try:
        x509_csr_check['SAN'] = ' '.join(x509_csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        x509_csr_check['SAN'] = 'No SAN'

    response = await render(context={'csr': x509_csr_check})
    response.add_cookie('csr', x509_csr_check['csr'])
    return response


@app.get("/csr/sign")
async def csr_sign(request):
    csr = request.cookies.get("csr")
    if csr is None:
        return text("No CSR")
    x509_csr = x509.load_pem_x509_csr(csr.encode('utf-8'))
    return text(x509_csr.public_bytes(encoding=serialization.Encoding.PEM).decode('ASCII'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000)
