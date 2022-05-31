FROM openresty/openresty:bionic

# install dependencies
RUN ["luarocks", "install", "lua-resty-session"]
RUN ["luarocks", "install", "lua-resty-http"]
RUN ["luarocks", "install", "lua-resty-jwt"]

# install test dependencies
RUN ["apt-get", "update"]
RUN ["apt-get", "install", "-y", "git"]
RUN ["luarocks", "install", "busted"]
RUN ["luarocks", "install", "LuaSocket"]
RUN ["luarocks", "install", "serpent"]
RUN ["luarocks", "install", "dkjson"]
RUN ["luarocks", "install", "luacov"]

ADD lib/resty/openidc.lua /usr/local/openresty/lualib/resty/openidc.lua

# mount tests
ADD tests/spec /spec

CMD busted -C spec -o plainTerminal . && (test -z "$coverage" || (\
    luacov -c /spec/luacov/settings.luacov && \
    cat /spec/luacov/luacov.report.out ) )
