# Build image running nginx with heartbleed, sslv2 (breach), sslv3 (poodle)
FROM ubuntu:12.04

RUN sed -i 's/archive/old-releases/g' /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y wget gcc make openssl perl-modules zlib1g-dev

WORKDIR /code

RUN wget --no-check-certificate https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz \
    \
    && tar -zxf openssl-1.0.1f.tar.gz \
    && cd /code/openssl-1.0.1f \
    \
    && ./config --prefix=/usr/local --openssldir=/usr/lib/ssl -DOPENSSL_USE_BUILD_DATE shared \
        enable-zlib enable-ssl2 enable-rc5 enable-rc2 enable-GOST enable-cms enable-md2 \
        enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa enable-seed enable-camellia \
        enable-idea enable-rfc3779 enable-ec_nistp_64_gcc_128 \
    && make \
    && make -i install \
    && cd /code \
    && rm -rf /code/openssl-1.0.1f*

RUN wget --no-check-certificate https://nginx.org/download/nginx-1.2.9.tar.gz \
    \
    && tar -zxf nginx-1.2.9.tar.gz \
    && cd /code/nginx-1.2.9 \
    && ./configure --with-cc-opt="-I/usr/local/include/openssl" \
                    --with-ld-opt="-L/usr/local/lib -ldl -Wl,-rpath,/usr/local/lib" \
                    --prefix=/usr/local/nginx \
                    --with-http_ssl_module \
                    --without-http_rewrite_module \
                    --without-http_gzip_module \
    && make \
    && make install \
    && cd /code \
    && rm -rf /code/nginx-1.2.9*

# forward request and error logs to docker log collector
RUN ln -sf /dev/stdout /usr/local/nginx/logs/access.log \
    && ln -sf /dev/stderr /usr/local/nginx/logs/error.log

RUN openssl req -x509 -newkey rsa:2048 \
    -keyout /usr/local/nginx/conf/cert.key \
    -out /usr/local/nginx/conf/cert.pem \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" \
    -days 365 -nodes

CMD ["/usr/local/nginx/sbin/nginx", "-g", "daemon off;"]