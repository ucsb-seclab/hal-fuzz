## -*- docker-image-name: "hal-fuzz" -*-
FROM ubuntu:18.04
MAINTAINER edg@cs.ucsb.edu
RUN useradd -s /bin/bash -m halfuzz
RUN printf omgwtfbbq\\nomgwtfbbq | passwd halfuzz 
RUN apt-get update && apt-get install -y sudo automake virtualenvwrapper python3-pip python-pip python3-dev python-dev build-essential libxml2-dev \
                      libxslt1-dev git libffi-dev cmake libreadline-dev libtool debootstrap debian-archive-keyring \
                      libglib2.0-dev libpixman-1-dev screen binutils-multiarch nasm vim libssl-dev 
COPY --chown=halfuzz . /home/halfuzz/hal-fuzz
RUN cd /home/halfuzz/hal-fuzz/ && ./setup.sh

USER halfuzz
WORKDIR /home/halfuzz/


