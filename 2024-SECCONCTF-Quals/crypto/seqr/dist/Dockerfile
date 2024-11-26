FROM python:3.12.7-slim-bookworm
RUN apt update -y && apt install -y socat && apt clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir ecdsa[gmpy2]==0.19.0 pycryptodome==3.21.0
COPY server.py /app/server.py

CMD ["socat", "TCP-L:13337,fork,reuseaddr", "EXEC:'python /app/server.py'"]
