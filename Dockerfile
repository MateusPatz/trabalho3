FROM debian:11

RUN apt update && apt install python3 python3-pip -y && pip3 install cryptography
