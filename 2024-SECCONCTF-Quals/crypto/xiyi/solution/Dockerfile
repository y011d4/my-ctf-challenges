FROM sagemath/sagemath:latest

WORKDIR /app

RUN sage -pip install --no-cache tqdm==4.66.5 pwntools==4.13.1
COPY solve.sage /app/solve.sage

CMD ["sage", "/app/solve.sage"]
