FROM python:3.12.7-slim-bookworm
RUN apt update -y && apt install -y socat && apt clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir pycryptodome==3.21.0
COPY lib.py params.py server.py /app/

CMD ["socat", "TCP-L:13333,fork,reuseaddr", "EXEC:'python /app/server.py'"]
