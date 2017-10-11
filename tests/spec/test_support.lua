local url = require("socket.url")
local serpent = require("serpent")

local test_support = {}

local DEFAULT_OIDC_CONFIG = {
   redirect_uri_path = "/redirect_uri",
   discovery = {
      authorization_endpoint = "http://localhost/authorize",
      token_endpoint = "http://localhost/token",
      token_endpoint_auth_methods_supported = { "client_secret_post" }
   },
   client_id = "client_id",
   client_secret = "client_secret",
   ssl_verify = "no",
   redirect_uri_scheme = 'http',
}

local DEFAULT_CONFIG_TEMPLATE = [[
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
                ngx.status = 500
                ngx.say(err)
                ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
              end
            }
            rewrite ^/default/(.*)$ /$1  break;
            proxy_pass http://localhost:80;
        }

    }
}
]]

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
  local config = DEFAULT_CONFIG_TEMPLATE:gsub("OIDC_CONFIG",
                                              serpent.block(oidc_config, {comment = false }))
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

return test_support
