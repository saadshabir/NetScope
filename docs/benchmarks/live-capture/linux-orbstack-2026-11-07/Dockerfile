FROM rust:1.93.1-bookworm@sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31
ENV LANG=C LC_ALL=C CARGO_TARGET_DIR=/bench/target
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 tcpreplay time python3 libpcap-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN git config --global --add safe.directory /source && mkdir -p /bench
WORKDIR /source
CMD ["sleep", "infinity"]
