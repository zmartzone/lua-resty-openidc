FROM openresty/openresty:xenial

ADD lib/resty/openidc.lua /usr/local/openresty/lualib/resty/openidc.lua

# install dependencies
RUN ["luarocks", "install", "lua-resty-session"]
RUN ["luarocks", "install", "lua-resty-http"]
RUN ["luarocks", "install", "lua-resty-jwt"]

# install test dependencies
RUN ["luarocks", "install", "busted"]
RUN ["luarocks", "install", "LuaSocket"]

# mount tests
ADD tests/spec /spec

CMD busted -C spec -o plainTerminal .
