FROM ubuntu:22.04
MAINTAINER kavin<kavin.mp@zohocorp.com>

SHELL ["/bin/bash", "-c"]
WORKDIR /root/install

ENV http_proxy=http://192.168.100.100:3128 https_proxy=http://192.168.100.100:3128
RUN yes "yes" | apt update -y --allow-unauthenticated
RUN yes "yes" | apt install -y wget --allow-unauthenticated
RUN yes "yes" | apt install -y clang --allow-unauthenticated
RUN yes "yes" | apt install -y llvm --allow-unauthenticated
RUN yes "yes" | apt install -y libelf-dev --allow-unauthenticated
RUN yes "yes" | apt install -y libc6-dev-i386 --allow-unauthenticated
RUN yes "yes" | apt install -y gcc-multilib --allow-unauthenticated
RUN yes "yes" | apt install -y libbpf-dev --allow-unauthenticated
RUN yes "yes" | apt install -y make --allow-unauthenticated

ENV http_proxy=
ENV https_proxy=
WORKDIR /root/install/

