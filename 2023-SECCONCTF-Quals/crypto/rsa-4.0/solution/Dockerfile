FROM sagemath/sagemath:10.0

WORKDIR /app

RUN sage -pip install --no-cache-dir pycryptodome==3.18.0

COPY solve.sage output.txt /app/

CMD ["/usr/bin/sage", "solve.sage"]
