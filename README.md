# SimpleCA
An extremely simple CA web application for educational purposes. The web application allows you to upload and view a CSR and download a certificate generated from it. A chain of Root CA - Intermediate CA - Certificate is used. The generated certificate allows SAN and sets the IssuerName, BasicConstrains, KeyUsage and AuthorityKeyIdentifier fields to be accepted by modern browsers.

## Plain Python
### Requirements
The script was tested with Python version 3.10.

The following package is required for the setup
* [cryptography](https://pypi.org/project/cryptography/)

The following packages are required for the server
* [sanic](https://pypi.org/project/sanic/)
* [sanic-ext](https://pypi.org/project/sanic-ext/)
* [jinja2](https://pypi.org/project/Jinja2/)

The Python environment is also available as a [Poetry](https://python-poetry.org/) definition.

### Setup
The setup.py generates the necessary Root CA and Intermediate CA certificates.

### Server
The server.py starts a web server built with the [Sanic](https://sanic.dev/en/) framework.

## Docker
The Dockerfile creates an image that is immediately ready for use. The container started from the image provides a web server on port 80.

A prebuild docker image is available on Dockerhub: <https://hub.docker.com/r/zepb/simpleca>
```
docker run -p 80:80 --name simpleca zepb/simpleca
```

## Usage
There are 4 options available on the website.
* CSR Upload - Upload and view the CSR file
* Certificate Download - Download the created certificate
* Download Root CA Certificate
* Download Intermediate CA Certificate

When a CSR is uploaded, a new process is started and a cookie with the process number is stored. A certificate can be created within the process, which can then be downloaded. As long as no new process is started, the created certificate can be downloaded as often as required. If no process has been started yet, the message "No Process" is displayed under Certificate Download.
