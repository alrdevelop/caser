FROM ubuntu:latest
LABEL Name=carservice Version=1.0.1

#Install common packages
RUN apt-get upgrade && apt-get update \
    && apt-get install -y git g++ cmake make pkg-config libssl-dev zlib1g-dev libgtest-dev libspdlog-dev libmicrohttpd-dev libpq-dev postgresql-server-dev-all libtool autotools-dev automake

#Install libhttpserver
RUN git clone https://github.com/etr/libhttpserver.git \
    && cd libhttpserver && ./bootstrap && mkdir build && cd build \
    && ../configure && make && make install
RUN rm -rf libhttpserver
RUN git clone https://github.com/gost-engine/engine && cd engine && git submodule update --init \
    && mkdir build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release .. \
    && cmake --build . --config Release \
    && cmake --build . --target install --config Release
RUN rm -rf engine

RUN git clone https://github.com/jtv/libpqxx.git && cd libpqxx && cmake . && cmake --build . && cmake --install .
RUN rm -rf libpqxx

#Insatll new dynamic libraries
RUN ldconfig

COPY ./conf/openssl.conf /usr/lib/ssl/openssl.cnf

#Build and run app
COPY ./src /usr/src/caserver
WORKDIR /usr/src/caserver/
RUN cmake . && make && mv /usr/src/caserver/caserver /usr/bin/caserver

RUN rm -rf /usr/src/caserver


CMD ["caserver"]
