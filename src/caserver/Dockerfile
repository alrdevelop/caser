FROM ubuntu:latest
LABEL Name=carservice Version=1.0.1

#Install common packages
RUN apt-get update \
    && apt-get install -y git g++ cmake make libssl-dev zlib1g-dev libgtest-dev libspdlog-dev libmicrohttpd-dev libpq-dev postgresql-server-dev-all libpqxx-dev libtool autotools-dev automake\
    && apt-get clean && rm -rf /var/lib/apt/lists/* 

#Install libhttpserver
RUN git clone https://github.com/etr/libhttpserver.git \
    && cd libhttpserver && ./bootstrap && mkdir build && cd build \
    && ../configure && make && make install

RUN git clone https://github.com/gost-engine/engine && cd engine && git submodule update --init \
    && mkdir build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release .. \
    && cmake --build . --target install --config Release
    

#Insatll new dynamic libraries
RUN ldconfig

#Build and run app
COPY ./src /usr/src/caserver
WORKDIR /usr/src/caserver/
RUN cmake . && make

CMD ["./caserver"]
