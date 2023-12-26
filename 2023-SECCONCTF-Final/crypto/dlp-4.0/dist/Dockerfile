FROM sagemath/sagemath:10.1
RUN sudo apt update -y && sudo apt install -y socat && sudo apt clean && sudo rm -rf /var/lib/apt/lists/*

RUN sage -pip install --no-cache-dir pycryptodome==3.19.0
COPY problem.sage /home/sage/problem.sage

CMD ["socat", "TCP-L:8888,fork,reuseaddr", "EXEC:'sage problem.sage'"]
