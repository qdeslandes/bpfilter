FROM ubuntu:24.10

RUN apt-get update && apt-get install --no-install-recommends -y \
    autoconf \
    automake \
    bison \
    clang-tidy \
    clang-format \
    cmake \
    doxygen \
    flex \
    furo \
    g++ \
    git \
    iproute2 \
    iputils-ping \
    lcov \
    libbenchmark-dev \
    libbpf-dev \
    libc-dev \
    libcmocka-dev \
    libgit2-dev \
    libnl-3-dev \
    libtool \
    linux-tools-common \
    make \
    pkgconf \
    python3-breathe \
    python3-dateutil \
    python3-git \
    python3-pip \
    python3-scapy \
    python3-setuptools \
    python3-sphinx && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --break-system-packages linuxdoc
