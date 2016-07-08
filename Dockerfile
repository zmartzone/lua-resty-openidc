FROM openresty/openresty:trusty

MAINTAINER Asbjørn Ulsberg <asbjorn@ulsberg.no>
RUN apt-get install -y libssl-dev
RUN apt-get install -y git
RUN /usr/local/openresty/luajit/bin/luarocks install lua-resty-openidc