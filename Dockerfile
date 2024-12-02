#
# Dockerfile for arm64 build
#
FROM ubuntu:24.04
RUN apt-get update
RUN apt-get install -y build-essential cmake git python3 python3-pip python3-venv

WORKDIR /home/build-dir

COPY . .
RUN cmake -S . -B build
RUN cmake --build build -j10
WORKDIR /home/build-dir/build
RUN ctest --output-on-failure
WORKDIR /home/build-dir
