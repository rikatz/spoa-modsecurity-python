FROM debian:10-slim as build

RUN apt-get update \
    && apt-get -y dist-upgrade \
    && apt-get install -y --no-install-recommends \
    automake \
    cmake \
    curl \
    doxygen \
    g++ \
    git \
    libcurl4-gnutls-dev \
    libgeoip-dev \
    liblua5.3-dev \
    libpcre++-dev \
    libtool \
    libxml2-dev \
    make \
    ruby \
    wget \
    python3-pip \
    liblmdb0 \
    liblmdb-dev \
    libyajl2 \
    libyajl-dev \
    libfuzzy2 \
    pkg-config \
    python3-dev \
    python3-venv \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY build-modsecurity.sh /tmp/
RUN chmod +x /tmp/build-modsecurity.sh && /tmp/build-modsecurity.sh

FROM debian:10-slim as runtime-image
RUN apt-get update \
    && apt-get -y dist-upgrade \
    && apt-get install -y --no-install-recommends \
    python3 \
    liblmdb0 \
    libyajl2 \
    libfuzzy2 \
    libcurl3-gnutls \
    libxml2 \
    liblua5.3-0 \
    libgeoip1 \
    libpython3.7 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/app/bin:$PATH" \
    RULES=/app/block-localhost.conf
COPY --from=build /usr/lib/libmodsecurity.so /usr/lib/
COPY --from=build /app/modsecurity/lib/python3.7/* /usr/local/lib/python3.7/dist-packages/
COPY --from=build /app/spoa /usr/bin/
COPY rules/block-localhost.conf modsecurity.py /app/

RUN /sbin/ldconfig

CMD [ "/usr/bin/spoa", "-f", "/app/modsecurity.py"]

