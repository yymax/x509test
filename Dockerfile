FROM dockerfile/python:latest
MAINTAINER dweinstein <dweinst@insitusec.com>

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -qq -y --no-install-recommends openssl build-essential libssl-dev libffi-dev \
      python3-dev python3-pip

ADD requirements.txt /tmp/requirements.txt
RUN cd /tmp && pip3 install -r requirements.txt

WORKDIR /opt/app
ENTRYPOINT ["python3", "/opt/app/x509test.py"]
ADD . /opt/app/

