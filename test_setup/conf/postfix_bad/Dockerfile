From ubuntu:trusty
MAINTAINER Elliott Ye

# Set noninteractive mode for apt-get
ENV DEBIAN_FRONTEND noninteractive

# Update
RUN apt-get update

# Start editing
# Install package here for cache
RUN apt-get -y install supervisor postfix sasl2-bin opendkim opendkim-tools

# Add files
COPY assets/install.sh /opt/install.sh

RUN mkdir -p /etc/postfix/certs \
    && openssl req -x509 -newkey rsa:2048 \
    -days 365 -nodes \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" \
    -keyout /etc/postfix/certs/cert-rsa.key \
    -out /etc/postfix/certs/cert-rsa.crt

# Run
CMD /opt/install.sh;/usr/bin/supervisord -c /etc/supervisor/supervisord.conf
