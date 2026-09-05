FROM openresty/openresty:jammy

# install dependencies
RUN ["luarocks", "install", "lua-resty-session", "4.2.0-1"]
RUN ["luarocks", "install", "lua-resty-http"]
RUN ["luarocks", "install", "lua-resty-jwt"]

# install test dependencies
RUN ["luarocks", "install", "busted"]
RUN ["luarocks", "install", "LuaSocket"]
RUN ["luarocks", "install", "dkjson"]
RUN ["luarocks", "install", "luacov"]

ADD lib/resty/openidc.lua /usr/local/openresty/lualib/resty/openidc.lua
ADD tests/vendor/serpent.lua /usr/local/openresty/lualib/serpent.lua

# mount tests
ADD tests/spec /spec
RUN mkdir -p /usr/local/openresty/nginx/client_body_temp \
    && chown -R nobody:nogroup /spec /usr/local/openresty/nginx

USER nobody

CMD ["sh", "-c", "busted -C spec -o plainTerminal . && (test -z \"$coverage\" || (luacov -c /spec/luacov/settings.luacov && cat /spec/luacov/luacov.report.out))"]
