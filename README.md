#SimpleCA
An extremely simple CA web application for educational purposes. The web application allows you to upload and view a CSR and download a certificate generated from it. A chain of Root CA - Intermediate CA - Certificate is used.

## Usage
### Requirements
The script was tested with Python version 3.10.

The following package is required for the setup
* [cryptography](https://pypi.org/project/cryptography/)

The following packages are required for the server
* [sanic](https://pypi.org/project/sanic/)
* [sanic-ext](https://pypi.org/project/sanic-ext/)
* [jinja2](https://pypi.org/project/Jinja2/)

### Setup
The setup.py generates the necessary Root CA and Intermediate CA certificates.

### Server
The server.py starts a web server built with the [Sanic](https://sanic.dev/en/) framework.

## Docker
The Dockerfile creates an image that is immediately ready for use. The container started from the image provides a web server on port 80.
