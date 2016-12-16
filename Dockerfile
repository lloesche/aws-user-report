FROM alpine

MAINTAINER Lukas Loesche "lloesche@fedoraproject.org"

ADD report.py /bin/
ADD requirements.txt /tmp/

RUN apk add --no-cache python3 && \
    python3 -m ensurepip && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install --upgrade pip setuptools && \
    pip3 install -r /tmp/requirements.txt && \
    rm -r /root/.cache

ENTRYPOINT ["/bin/report.py"]
