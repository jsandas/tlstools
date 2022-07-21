FROM mariadb:10.6

COPY config.cnf /etc/mysql/conf.d/

RUN openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/mysql/cert.key \
    -out /etc/mysql/cert.pem \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" \
    -days 365 -nodes

RUN chown mysql:mysql /etc/mysql/cert.key /etc/mysql/cert.pem
