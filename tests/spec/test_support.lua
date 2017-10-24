local http = require("socket.http")
local url = require("socket.url")
local serpent = require("serpent")

local test_support = {}

local DEFAULT_OIDC_CONFIG = {
   redirect_uri_path = "/default/redirect_uri",
   discovery = {
      authorization_endpoint = "http://127.0.0.1/authorize",
      token_endpoint = "http://127.0.0.1/token",
      token_endpoint_auth_methods_supported = { "client_secret_post" },
      issuer = "http://127.0.0.1/",
      jwks_uri = "http://127.0.0.1/jwk",
   },
   client_id = "client_id",
   client_secret = "client_secret",
   ssl_verify = "no",
   redirect_uri_scheme = 'http',
}

local DEFAULT_ID_TOKEN = {
  sub = "subject",
  iss = "http://127.0.0.1/",
  aud = "client_id",
  iat = os.time(),
  exp = os.time() + 3600,
}

local DEFAULT_ACCESS_TOKEN = {
  exp = os.time() + 3600,
}

local DEFAULT_TOKEN_HEADER = {
  typ = "JWT",
  alg = "RS256",
}

function test_support.load(file_name)
  local file = assert(io.open(file_name, "r"))
  local content = file:read("*all")
  assert(file:close())
  return content;
end

function test_support.trim(s)
  return s:gsub("^%s*(.-)%s*$", "%1")
end

local DEFAULT_JWT_VERIFY_SECRET = test_support.load("/spec/private_rsa_key.pem")

local DEFAULT_JWK = test_support.load("/spec/rsa_key_jwk_with_x5c.json")

local DEFAULT_VERIFY_OPTS = {
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
        secret = [=[
JWT_VERIFY_SECRET]=]
    }

    resolver      8.8.8.8;
    default_type  application/octet-stream;
    server {
        log_subrequest on;

        listen      80;
        #listen     443 ssl;
        #ssl_certificate     certificate-chain.crt;
        #ssl_certificate_key private.key;

        location /jwt {
            content_by_lua_block {
                local jwt_content = {
                  header = TOKEN_HEADER,
                  payload = ACCESS_TOKEN
                }
                local jwt = require "resty.jwt"
                local jwt_token = jwt:sign(secret, jwt_content)
                ngx.header.content_type = 'text/plain'
                ngx.say(jwt_token)
            }
        }

        location /jwk {
            content_by_lua_block {
                ngx.header.content_type = 'application/json;charset=UTF-8'
                ngx.say([=[JWK]=])
            }
        }

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
                local auth = ngx.req.get_headers()["Authorization"]
                ngx.log(ngx.ERR, "token authorization header: " .. (auth and auth or ""))
                ngx.header.content_type = 'application/json;charset=UTF-8'
                local id_token = ID_TOKEN
                local nonce_file = assert(io.open("/tmp/nonce", "r"))
                id_token.nonce = nonce_file:read("*all")
                assert(nonce_file:close())
                local jwt_content = {
                  header = TOKEN_HEADER,
                  payload = id_token
                }
                local jwt = require "resty.jwt"
                local jwt_token = jwt:sign(secret, jwt_content)
                ngx.say([=[{
  "access_token":"a_token",
  "expires_in":3600,
  "refresh_token":"r_token",
  "id_token": "]=] .. jwt_token .. [=["
}]=])
            }
        }

        location /verify_bearer_token {
            content_by_lua_block {
                local json, err, token = oidc.bearer_jwt_verify(VERIFY_OPTS)
                if err then
                  ngx.status = 401
                  ngx.log(ngx.ERR, "Invalid token: " .. err)
                else
                  ngx.status = 204
                  ngx.log(ngx.ERR, "Valid token: " .. (require "cjson").encode(json))
                end
            }
        }

    }
}
]]

-- URL escapes s and doubles the percent signs so the result can be
-- used as a pattern
function test_support.urlescape_for_regex(s)
  return url.escape(s):gsub("%%", "%%%%"):gsub("%%%%2e", "%%%.")
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
  local id_token = merge(merge({}, DEFAULT_ID_TOKEN), custom_config["id_token"] or {})
  local verify_opts = merge(merge({}, DEFAULT_VERIFY_OPTS), custom_config["verify_opts"] or {})
  local access_token = merge(merge({}, DEFAULT_ACCESS_TOKEN), custom_config["access_token"] or {})
  local token_header = merge(merge({}, DEFAULT_TOKEN_HEADER), custom_config["token_header"] or {})
  for _, k in ipairs(custom_config["remove_id_token_claims"] or {}) do
    id_token[k] = nil
  end
  local config = DEFAULT_CONFIG_TEMPLATE
    :gsub("OIDC_CONFIG", serpent.block(oidc_config, {comment = false }))
    :gsub("ID_TOKEN", serpent.block(id_token, {comment = false }))
    :gsub("TOKEN_HEADER", serpent.block(token_header, {comment = false }))
    :gsub("ACCESS_TOKEN", serpent.block(access_token, {comment = false }))
    :gsub("JWT_VERIFY_SECRET", custom_config["jwt_verify_secret"] or DEFAULT_JWT_VERIFY_SECRET)
    :gsub("VERIFY_OPTS", serpent.block(verify_opts, {comment = false }))
    :gsub("JWK", custom_config["jwk"] or DEFAULT_JWK)
  out:write(config)
end

-- starts a server instance with some customizations of the configuration.
-- expects custom_config to be a table with:
-- - oidc_opts is a table containing options that are accepted by oidc.authenticate
-- - id_token is a table containing id_token claims
-- - remove_id_token_claims is an array of claims to remove from the id_token
-- - verify_opts is a table containing options that are accepted by oidc.bearer_jwt_verify
-- - jwt_signature_alg algorithm to use for signing JWTs
-- - jwt_verify_secret the secret to use when verifying the secret
-- - access_token is a table containing claims for the access token provided by /jwt
-- - token_header is a table containing claims for the header used by
--   /jwt as well as the id token
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

-- tries hard to stop the server started by test_support.start_server
function test_support.stop_server()
  local pid = test_support.load("/tmp/server/logs/nginx.pid")
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

-- grabs a URI parameter value out of the location header of a response
function test_support.grab(headers, param)
  return string.match(headers.location, ".*" .. param .. "=([^&]+).*")
end

-- makes the nonce used with the authorization request available to
-- the token endpoint mock
function test_support.register_nonce(headers)
  local nonce = test_support.grab(headers, 'nonce')
  local nonce_file = assert(io.open("/tmp/nonce", "w"))
  nonce_file:write(nonce)
  assert(nonce_file:close())
end

-- returns a Cookie header value based on all cookies requested via
-- Set-Cookie inside headers
function test_support.extract_cookies(headers)
   local pair = headers["set-cookie"] or ''
   local semi = pair:find(";")
   if semi then
      pair = pair:sub(1, semi - 1)
   end
   return pair
end

-- performs the full authorization grant flow
-- returns the state parameter, the http status of the code response
-- and the cookies set by the last response
function test_support.login()
  local _, _, headers = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  local state = test_support.grab(headers, 'state')
  test_support.register_nonce(headers)
  _, status, redir_h = http.request({
        url = "http://127.0.0.1/default/redirect_uri?code=foo&state=" .. state,
        headers = { cookie = test_support.extract_cookies(headers) },
        redirect = false
  })
  return state, status, test_support.extract_cookies(redir_h)
end

local a = require 'luassert'
local say = require("say")

local function error_log_contains(state, args)
  local case_insensitive = args[2] and true or false
  local log = test_support.load("/tmp/server/logs/error.log")
  if case_insensitive then
    return log:lower():find(args[1]:lower()) and true or false
  else
    return log:find(args[1]) and true or false
  end
end

say:set("assertion.error_log_contains.positive", "Expected error log to contain: %s")
say:set("assertion.error_log_contains.negative", "Expected error log not to contain: %s")
a:register("assertion", "error_log_contains", error_log_contains,
           "assertion.error_log_contains.positive",
           "assertion.error_log_contains.negative")

return test_support
