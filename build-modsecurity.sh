#!/bin/bash
## Based in modsecurity Dockerfile 
# Ref: https://github.com/coreruleset/modsecurity-docker/blob/master/v3-nginx/Dockerfile

WORKDIR=/sources

mkdir -p ${WORKDIR} && cd ${WORKDIR}

cd ${WORKDIR}
wget --quiet https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz \
 && tar -xvzf ssdeep-2.14.1.tar.gz \
 && cd ssdeep-2.14.1 \
 && ./configure \
 && make install

cd ${WORKDIR}
git clone https://github.com/SpiderLabs/ModSecurity --branch v3.0.4 --depth 1 \
 && cd ModSecurity \
 && ./build.sh \
 && git submodule init \
 && git submodule update \
 #&& ./configure --prefix=/usr --with-yajl=${WORKDIR}/yajl/build/yajl-2.1.0/ \
 ./configure --prefix=/usr --with-yajl --with-lmdb \
 && make install

cd ${WORKDIR}
python3 -m venv /app/modsecurity && source /app/modsecurity/bin/activate
export PATH="/app/bin:$PATH"
pip3 install pybind11 setuptools \
 && git clone https://github.com/pymodsecurity/pymodsecurity \
 && cd pymodsecurity \
 && python3 setup.py install

cd ${WORKDIR}
export HAPROXY_MAJOR=2.3
export HAPROXY_VERSION=2.3.0
curl -fsSLo haproxy.tar.gz https://www.haproxy.org/download/${HAPROXY_MAJOR}/src/haproxy-${HAPROXY_VERSION}.tar.gz \
 && mkdir -p ${WORKDIR}/haproxy \
 && tar xzf haproxy.tar.gz -C ${WORKDIR}/haproxy --strip-components=1 \
 && cd haproxy/contrib/spoa_server \
 && USE_PYTHON=1 make \
 && cp spoa /app/spoa

rm -rf ${WORKDIR}





