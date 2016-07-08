FROM openresty/openresty:trusty

MAINTAINER Asbjørn Ulsberg <asbjorn@ulsberg.no>
RUN wget http://luarocks.org/releases/luarocks-2.3.0.tar.gz
RUN tar zxpf luarocks-2.3.0.tar.gz
RUN cd luarocks-2.3.0
RUN ./configure; sudo make bootstrap
RUN sudo luarocks install luasocket
RUN luarocks install lua-resty-http
RUN luarocks install lua-resty-http
RUN luarocks install lua-resty-session
RUN luarocks install lua-resty-jwt
RUN luarocks install lua-resty-hmac
RUN luarocks install lua-resty-openidc