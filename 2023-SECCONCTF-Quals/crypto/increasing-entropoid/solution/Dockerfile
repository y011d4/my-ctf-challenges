FROM sagemath/sagemath:10.0

WORKDIR /app

RUN sage -pip install --no-cache-dir pycryptodome==3.18.0 z3-solver==4.12.2.0 tqdm==4.66.1

COPY solve.sage output.txt /app/

CMD ["/usr/bin/sage", "solve.sage"]
