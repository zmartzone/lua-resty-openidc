local url = require("socket.url")
local serpent = require("serpent")

local test_support = {}

local DEFAULT_OIDC_CONFIG = {
   redirect_uri_path = "/default/redirect_uri",
   discovery = {
      authorization_endpoint = "http://localhost/authorize",
      token_endpoint = "http://127.0.0.1/token",
      token_endpoint_auth_methods_supported = { "client_secret_post" },
      issuer = "https://localhost/",
   },
   client_id = "client_id",
   client_secret = "client_secret",
   ssl_verify = "no",
   redirect_uri_scheme = 'http',
}

local DEFAULT_ID_TOKEN = {
  sub = "subject",
  iss = "https://localhost/",
  aud = "client_id",
  iat = os.time(),
  exp = os.time() + 3600,
}

local DEFAULT_CONFIG_TEMPLATE = [=[
worker_processes  1;
pid       /tmp/server/logs/nginx.pid;
error_log /tmp/server/logs/error.log debug;

events {
    worker_connections  1024;
}

http {
    access_log /tmp/server/logs/access.log;
    lua_package_path '~/lua/?.lua;;';
    lua_shared_dict discovery 1m;
    init_by_lua_block {
        oidc = require "resty.openidc"
    }

    resolver      8.8.8.8;
    default_type  application/octet-stream;
    server {
        log_subrequest on;

        listen      80;
        #listen     443 ssl;
        #ssl_certificate     certificate-chain.crt;
        #ssl_certificate_key private.key;

        location /t {
            echo "hello, world!";
        }

        location /default {
            access_by_lua_block {
              local opts = OIDC_CONFIG
              local oidc = require "resty.openidc"
              local res, err, target, session = oidc.authenticate(opts)
              if err then
                ngx.status = 401
                ngx.say(err)
                ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
              end
            }
            rewrite ^/default/(.*)$ /$1  break;
            proxy_pass http://localhost:80;
        }

        location /token {
            content_by_lua_block {
                ngx.req.read_body()
                ngx.log(ngx.ERR, "Received token request: " .. ngx.req.get_body_data())
                ngx.header.content_type = 'application/json;charset=UTF-8'
                local id_token = ID_TOKEN
                local nonce_file = assert(io.open("/tmp/nonce", "r"))
                id_token.nonce = nonce_file:read("*all")
                assert(nonce_file:close())
                local jwt_content = {
                  header = { typ = "JWT", alg = "HS256"},
                  payload = id_token
                }
                local jwt = require "resty.jwt"
                local jwt_token = jwt:sign("lua-resty-jwt", jwt_content)
                ngx.say([[{
  "access_token":"a_token",
  "expires_in":3600,
  "refresh_token":"r_token",
  "id_token": "]] .. jwt_token .. [["
}]])
            }
        }
    }
}
]=]

-- must double percents for Lua regexes
function test_support.urlescape_for_regex(s)
  return url.escape(s):gsub("%%", "%%%%")
end

local function merge(t1, t2)
  for k, v in pairs(t2) do
    if (type(v) == "table") and (type(t1[k] or false) == "table") then
      merge(t1[k], t2[k])
    else
      t1[k] = v
    end
  end
  return t1
end

local function write_config(out, custom_config)
  custom_config = custom_config or {}
  local oidc_config = merge(merge({}, DEFAULT_OIDC_CONFIG), custom_config["oidc_opts"] or {})
  local config = DEFAULT_CONFIG_TEMPLATE
     :gsub("OIDC_CONFIG", serpent.block(oidc_config, {comment = false }))
     :gsub("ID_TOKEN", serpent.block(DEFAULT_ID_TOKEN, {comment = false }))
  out:write(config)
end

function test_support.start_server(custom_config)
  assert(os.execute("rm -rf /tmp/server"), "failed to remove old server dir")
  assert(os.execute("mkdir -p /tmp/server/conf"), "failed to create server dir")
  assert(os.execute("mkdir -p /tmp/server/logs"), "failed to create log dir")
  local out = assert(io.open("/tmp/server/conf/nginx.conf", "w"))
  write_config(out, custom_config)
  assert(out:close())
  assert(os.execute("openresty -c /tmp/server/conf/nginx.conf > /dev/null"), "failed to start nginx")
end

local function kill(pid, signal)
  if not signal then
    signal = ""
  else
    signal = "-" .. signal .. " "
  end
  return os.execute("/bin/kill " .. signal .. pid)
end

local function is_running(pid)
  return kill(pid, 0)
end

function test_support.stop_server()
  local pid_file = assert(io.open("/tmp/server/logs/nginx.pid", "r"))
  local pid = pid_file:read("*all")
  assert(pid_file:close())
  local sleep = 0.1
  for a = 1, 5
  do
    if is_running(pid) then
      kill(pid)
      os.execute("sleep " .. sleep)
      sleep = sleep * 2
    else
      break
    end
  end
  if is_running(pid) then
     print("forcing nginx to stop")
     kill(pid, 9)
     os.execute("sleep 0.5")
  end
end

function test_support.register_nonce(nonce)
  local nonce_file = assert(io.open("/tmp/nonce", "w"))
  nonce_file:write(nonce)
  assert(nonce_file:close())
end

local a = require 'luassert'
local say = require("say")

local function error_log_contains(state, args)
  local error_log = assert(io.open("/tmp/server/logs/error.log", "r"))
  local log = error_log:read("*all")
  assert(error_log:close())
  return log:find(args[1]) and true or false
end

say:set("assertion.error_log_contains.positive", "Expected error log to contain: %s")
say:set("assertion.error_log_contains.negative", "Expected error log not to contain: %s")
a:register("assertion", "error_log_contains", error_log_contains,
           "assertion.error_log_contains.positive",
           "assertion.error_log_contains.negative")

return test_support
