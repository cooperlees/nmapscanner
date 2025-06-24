FROM python:3-slim

RUN apt update && apt install -y nmap gcc libmariadb-dev

RUN mkdir -p /src/src/nmapscanner/tests
ADD setup.py /src
ADD src/nmapscanner/*.py /src/src/nmapscanner
ADD src/nmapscanner/tests/*.py /src/src/nmapscanner/tests

RUN pip install --no-cache-dir --upgrade pip setuptools && \
    cd /src && pip install .[mariadb] && \
    apt remove -y gcc libmariadb-dev && \
    apt clean all

CMD ["nmapscanner", "--help"]
