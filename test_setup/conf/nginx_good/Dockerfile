FROM nginx:1.23.0-alpine

RUN apk --no-cache upgrade \
    && apk --no-cache add openssl

RUN openssl req -x509 -newkey rsa:4096 \
    -days 365 -nodes \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" \
    -keyout /etc/nginx/conf.d/cert-rsa.key \
    -out /etc/nginx/conf.d/cert-rsa.pem

RUN openssl req -x509 -newkey ec:<(openssl ecparam -name secp384r1) \
    -days 365 -nodes \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" \
    -keyout /etc/nginx/conf.d/cert-ecc.key \
    -out /etc/nginx/conf.d/cert-ecc.pem

COPY default.conf /etc/nginx/conf.d/default.conf

# CMD ["/etc/nginx/sbin.d/nginx", "-g", "daemon off;"]