FROM python:3.10.12-bullseye

WORKDIR /

COPY server.py server.py
COPY setup.py setup.py
COPY sign.py sign.py
COPY templates/ templates/

# Install sanic dependencies
RUN pip install --no-cache-dir sanic
RUN pip install --no-cache-dir sanic-ext
RUN pip install --no-cache-dir jinja2

# Install x509 dependencies
RUN pip install --no-cache-dir cryptography

RUN python setup.py

EXPOSE 80
CMD ["python", "server.py"]
