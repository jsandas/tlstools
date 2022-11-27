FROM debian

RUN apt-get update && \
    apt-get install -y wget

RUN wget https://openrepos.net/sites/default/files/packages/71/openssl-blacklist_0.5-3_all.deb \
    && dpkg-deb -xv openssl-blacklist_0.5-3_all.deb / \
    && wget https://openrepos.net/sites/default/files/packages/71/openssl-blacklist-extra_0.5-3_all.deb \
    && dpkg-deb -xv openssl-blacklist-extra_0.5-3_all.deb / \
    && rm *.deb
