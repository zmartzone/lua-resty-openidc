FROM openresty/openresty:trusty

MAINTAINER Asbjørn Ulsberg <asbjorn@ulsberg.no>
RUN /usr/local/openresty/luajit/bin/luarocks install lua-resty-openidc