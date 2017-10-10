FROM openresty/openresty:xenial

ADD lib/resty/openidc.lua /usr/local/openresty/lualib/resty/openidc.lua

# install dependencies
RUN ["luarocks", "install", "lua-resty-session"]
RUN ["luarocks", "install", "lua-resty-http"]
RUN ["luarocks", "install", "lua-resty-jwt"]
RUN ["luarocks", "install", "lua-resty-jwt"]

# install test dependencies
RUN ["luarocks", "install", "busted"]
RUN ["luarocks", "install", "LuaSocket"]

ADD tests/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

# mount tests
ADD tests/spec /spec

CMD openresty && busted


