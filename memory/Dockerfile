FROM ubuntu:trusty
MAINTAINER Virgil Security Inc. <support@virgilsecurity.com>

# Set the locale
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y -q
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --force-yes software-properties-common
RUN DEBIAN_FRONTEND=noninteractive apt-get update -y -q
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --force-yes build-essential
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --force-yes libpcre3-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --force-yes git
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --force-yes curl
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --force-yes wget
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --force-yes libssl-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --force-yes valgrind

ENV CMAKE_VERSION_MAJOR=3
ENV CMAKE_VERSION_MINOR=11
ENV CMAKE_VERSION_PATCH=1
ENV CMAKE_VERSION=${CMAKE_VERSION_MAJOR}.${CMAKE_VERSION_MINOR}.${CMAKE_VERSION_PATCH}

RUN cd && \
    wget https://cmake.org/files/v${CMAKE_VERSION_MAJOR}.${CMAKE_VERSION_MINOR}/cmake-${CMAKE_VERSION}-Linux-x86_64.sh && \
    bash cmake-${CMAKE_VERSION}-Linux-x86_64.sh --skip-license --exclude-subdir --prefix=/usr/local