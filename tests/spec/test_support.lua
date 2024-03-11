local http = require("socket.http")
local url = require("socket.url")
local serpent = require("serpent")

local test_support = {}

local DEFAULT_OIDC_CONFIG = {
   redirect_uri = "http://localhost/default/redirect_uri",
   logout_path = "/default/logout",
   discovery = {
      authorization_endpoint = "http://127.0.0.1/authorize",
      token_endpoint = "http://127.0.0.1/token",
      token_endpoint_auth_methods_supported = { "client_secret_post" },
      issuer = "http://127.0.0.1/",
      jwks_uri = "http://127.0.0.1/jwk",
      userinfo_endpoint = "http://127.0.0.1/user-info",
      id_token_signing_alg_values_supported = { "RS256", "HS256" },
   },
   client_id = "client_id",
   client_secret = "client_secret",
   ssl_verify = "no",
   keepalive = "yes"
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

function test_support.self_signed_jwt(payload, alg, signature)
  local function b64url(s)
    local dkjson = require "dkjson"
    local mime = require "mime"
    return mime.b64(dkjson.encode(s)):gsub('+','-'):gsub('/','_')
  end
  local header = b64url({
      typ = "JWT",
      alg = alg or "none"
  })
  return header .. "." .. b64url(payload) .. "." .. (signature or "")
end

local DEFAULT_JWT_SIGN_SECRET = test_support.load("/spec/private_rsa_key.pem")

local DEFAULT_JWK = test_support.load("/spec/rsa_key_jwk_with_x5c.json")

local DEFAULT_VERIFY_OPTS = {
}

local DEFAULT_INTROSPECTION_OPTS = {
  introspection_endpoint = "http://127.0.0.1/introspection",
  client_id = "client_id",
  client_secret = "client_secret",
}

local DEFAULT_TOKEN_RESPONSE_EXPIRES_IN = "3600"

local DEFAULT_TOKEN_RESPONSE_CONTAINS_REFRESH_TOKEN = "true"
local DEFAULT_REFRESHING_TOKEN_FAILS = "false"
local DEFAULT_FAKE_ACCESS_TOKEN_SIGNATURE = "false"
local DEFAULT_FAKE_ID_TOKEN_SIGNATURE = "false"
local DEFAULT_BREAK_ID_TOKEN_SIGNATURE = "false"
local DEFAULT_NONE_ALG_ID_TOKEN_SIGNATURE = "false"
local DEFAULT_REFRESH_RESPONSE_CONTAINS_ID_TOKEN = "true"

local DEFAULT_UNAUTH_ACTION = "nil"

local DEFAULT_DELAY_RESPONSE = "0"

local DEFAULT_INIT_TEMPLATE = [[
local test_globals = {}
local sign_secret = [=[
JWT_SIGN_SECRET]=]

if os.getenv('coverage') then
  require("luacov.runner")("/spec/luacov/settings.luacov")
end
test_globals.oidc = require "resty.openidc"
test_globals.cjson = require "cjson"
test_globals.delay = function(delay_response)
  if delay_response > 0 then
    ngx.sleep(delay_response / 1000)
  end
end
test_globals.b64url = function(s)
  return ngx.encode_base64(test_globals.cjson.encode(s)):gsub('+','-'):gsub('/','_')
end
test_globals.create_jwt = function(payload, fake_signature)
  if not fake_signature then
    local jwt_content = {
      header = TOKEN_HEADER,
      payload = payload
    }
    local jwt = require "resty.jwt"
    return jwt:sign(sign_secret, jwt_content)
  else
    local header = test_globals.b64url({
        typ = "JWT",
        alg = "AB256"
    })
    return header .. "." .. test_globals.b64url(payload) .. ".NOT_A_VALID_SIGNATURE"
  end
end
test_globals.query_decorator = function(req)
  req.query = "foo=bar"
  return req
end
test_globals.body_decorator = function(req)
  local body = ngx.decode_args(req.body)
  body.foo = "bar"
  req.body = ngx.encode_args(body)
  return req
end
test_globals.jwks = [=[JWK]=]
return test_globals
]]

local DEFAULT_CONFIG_TEMPLATE = [[
worker_processes  1;
pid       /tmp/server/logs/nginx.pid;
error_log /tmp/server/logs/error.log debug;

events {
    worker_connections  1024;
}

http {
    access_log /tmp/server/logs/access.log;
    lua_package_path '~/lua/?.lua;/tmp/server/conf/?.lua;;';
    lua_shared_dict discovery 1m;
    init_by_lua_block {
        test_globals = require("test_globals")
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
                local jwt_token = test_globals.create_jwt(ACCESS_TOKEN, FAKE_ACCESS_TOKEN_SIGNATURE)
                ngx.header.content_type = 'text/plain'
                ngx.say(jwt_token)
            }
        }

        location /jwk {
            content_by_lua_block {
                ngx.log(ngx.ERR, "jwk uri_args: " .. test_globals.cjson.encode(ngx.req.get_uri_args()))
                ngx.header.content_type = 'application/json;charset=UTF-8'
                test_globals.delay(JWK_DELAY_RESPONSE)
                ngx.say(test_globals.jwks)
            }
        }

        location /t {
            echo "hello, world!";
        }

        location /default {
            access_by_lua_block {
              local opts = OIDC_CONFIG
              if opts.decorate then
                opts.http_request_decorator = opts.decorate == "body" and test_globals.body_decorator or test_globals.query_decorator
              end
              local res, err, target, session = test_globals.oidc.authenticate(opts, nil, UNAUTH_ACTION)
              if err then
                ngx.status = 401
                ngx.log(ngx.ERR, "authenticate failed: " .. err)
                ngx.say("authenticate failed: " .. err)
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
              end
              if not res or not res.access_token then
                ngx.log(ngx.ERR, "authenticate didn't return any access token")
              end
            }
            rewrite ^/default/(.*)$ /$1  break;
            proxy_pass http://localhost:80;
        }

        location /default-absolute {
            access_by_lua_block {
              local opts = OIDC_CONFIG
              if opts.decorate then
                opts.http_request_decorator = opts.decorate == "body" and test_globals.body_decorator or test_globals.query_decorator
              end
              local uri = ngx.var.scheme .. "://" .. ngx.var.host .. ngx.var.request_uri
              local res, err, target, session = test_globals.oidc.authenticate(opts, uri, UNAUTH_ACTION)
              if err then
                ngx.status = 401
                ngx.log(ngx.ERR, "authenticate failed: " .. err)
                ngx.say("authenticate failed: " .. err)
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
              end
              if not res or not res.access_token then
                ngx.log(ngx.ERR, "authenticate didn't return any access token")
              end
            }
            rewrite ^/default-absolute/(.*)$ /$1  break;
            proxy_pass http://localhost:80;
        }

        location /token {
            content_by_lua_block {
                ngx.req.read_body()
                ngx.log(ngx.ERR, "Received token request: " .. ngx.req.get_body_data())
                local auth = ngx.req.get_headers()["Authorization"]
                ngx.log(ngx.ERR, "token authorization header: " .. (auth and auth or ""))
                ngx.header.content_type = 'application/json;charset=UTF-8'
                local args = ngx.req.get_post_args()
                local id_token
                if args.grant_type == "authorization_code" then
                  id_token = ID_TOKEN
                else
                  id_token = REFRESH_ID_TOKEN
                end
                local access_token = "a_token"
                local refresh_token = "r_token"
                if args.grant_type == "authorization_code" then
                  local nonce_file = assert(io.open("/tmp/nonce", "r"))
                  id_token.nonce = nonce_file:read("*all")
                  assert(nonce_file:close())
                else
                  if REFRESHING_TOKEN_FAILS then
                    ngx.status = 400
                    ngx.say('{"error":"invalid_grant","error_description":"Refresh token expired"}')
                    ngx.exit(400)
                  end
                  access_token = access_token .. "2"
                  refresh_token = refresh_token .. "2"
                end
                local jwt_token
                if NONE_ALG_ID_TOKEN_SIGNATURE then
                  local header = test_globals.b64url({
                      typ = "JWT",
                      alg = "none"
                  })
                  jwt_token = header .. "." .. test_globals.b64url(id_token) .. "."
                else
                  jwt_token = test_globals.create_jwt(id_token, FAKE_ID_TOKEN_SIGNATURE)
                  if BREAK_ID_TOKEN_SIGNATURE then
                    jwt_token = jwt_token:sub(1, -6) .. "XXXXX"
                  end
                end
                local token_response = {
                  access_token = access_token,
                  expires_in = TOKEN_RESPONSE_EXPIRES_IN,
                  refresh_token = TOKEN_RESPONSE_CONTAINS_REFRESH_TOKEN and refresh_token or nil,
                }
                if args.grant_type == "authorization_code" or REFRESH_RESPONSE_CONTAINS_ID_TOKEN then
                  token_response.id_token = jwt_token
                end
                test_globals.delay(TOKEN_DELAY_RESPONSE)
                ngx.say(test_globals.cjson.encode(token_response))
            }
        }

        location /verify_bearer_token {
            content_by_lua_block {
                local opts = VERIFY_OPTS
                if opts.decorate then
                  opts.http_request_decorator = test_globals.query_decorator
                end
                local json, err, token = test_globals.oidc.bearer_jwt_verify(opts)
                if err then
                  ngx.status = 401
                  ngx.log(ngx.ERR, "Invalid token: " .. err)
                else
                  ngx.status = 204
                  ngx.log(ngx.ERR, "Valid token: " .. test_globals.cjson.encode(json))
                end
            }
        }

        location /discovery {
            content_by_lua_block {
                ngx.log(ngx.ERR, "discovery uri_args: " .. test_globals.cjson.encode(ngx.req.get_uri_args()))
                ngx.header.content_type = 'application/json;charset=UTF-8'
                test_globals.delay(DISCOVERY_DELAY_RESPONSE)
                ngx.say([=[{
  "authorization_endpoint": "http://127.0.0.1/authorize",
  "token_endpoint": "http://127.0.0.1/token",
  "token_endpoint_auth_methods_supported": [ "client_secret_post" ],
  "issuer": "http://127.0.0.1/",
  "jwks_uri": "http://127.0.0.1/jwk"
}]=])
            }
        }

        location /user-info {
            content_by_lua_block {
                test_globals.delay(USERINFO_DELAY_RESPONSE)
                local auth = ngx.req.get_headers()["Authorization"]
                ngx.log(ngx.ERR, "userinfo authorization header: " .. (auth and auth or ""))
                ngx.header.content_type = 'application/json;charset=UTF-8'
                ngx.say(test_globals.cjson.encode(USERINFO))
            }
        }

        location /user-info-signed {
            content_by_lua_block {
                local auth = ngx.req.get_headers()["Authorization"]
                ngx.header.content_type = 'application/jwt;charset=UTF-8'
                local signed_userinfo = test_globals.create_jwt(USERINFO)
                ngx.print(signed_userinfo)
            }
        }

        location /introspection {
            content_by_lua_block {
                ngx.req.read_body()
                ngx.log(ngx.ERR, "Received introspection request: " .. ngx.req.get_body_data())
                local auth = ngx.req.get_headers()["Authorization"]
                ngx.log(ngx.ERR, "introspection authorization header: " .. (auth and auth or ""))
                local cookie = ngx.req.get_headers()["Cookie"]
                if cookie then
                  if type(cookie) == "string" then
                    cookie = { cookie }
                  end
                  for _, c in ipairs(cookie) do
                    ngx.log(ngx.ERR, "cookie " .. c .. " in introspection call")
                  end
                else
                  ngx.log(ngx.ERR, "no cookie in introspection call")
                end
                ngx.header.content_type = 'application/json;charset=UTF-8'
                test_globals.delay(INTROSPECTION_DELAY_RESPONSE)
                ngx.say(test_globals.cjson.encode(INTROSPECTION_RESPONSE))
            }
        }

        location /introspect {
            content_by_lua_block {
                local opts = INTROSPECTION_OPTS
                if opts.decorate then
                  opts.http_request_decorator = test_globals.body_decorator
                end
                local json, err = test_globals.oidc.introspect(opts)
                if err then
                  ngx.status = 401
                  ngx.log(ngx.ERR, "Introspection error: " .. err)
                else
                  ngx.header.content_type = 'application/json;charset=UTF-8'
                  ngx.say(test_globals.cjson.encode(json))
                end
            }
        }

        location /access_token {
            content_by_lua_block {
                local access_token, err = test_globals.oidc.access_token(ACCESS_TOKEN_OPTS)
                if not access_token then
                  ngx.status = 401
                  ngx.log(ngx.ERR, "access_token error: " .. (err or 'no message'))
                else
                  ngx.header.content_type = 'text/plain'
                  ngx.say(access_token)
                end
            }
        }

        location /revoke_tokens {
          content_by_lua_block {
              local opts = OIDC_CONFIG
              local res, err, target, session = test_globals.oidc.authenticate(opts, nil, UNAUTH_ACTION)
              local r = test_globals.oidc.revoke_tokens(opts, session)
              ngx.header.content_type = 'text/plain'
              ngx.say('revoke-result: ' .. tostring(r))
          }
        }

        location /revocation {
            content_by_lua_block {
                ngx.req.read_body()
                ngx.log(ngx.ERR, "Received revocation request: " .. ngx.req.get_body_data())
                local auth = ngx.req.get_headers()["Authorization"]
                ngx.log(ngx.ERR, "revocation authorization header: " .. (auth and auth or ""))
                local cookie = ngx.req.get_headers()["Cookie"]
                if not cookie then
                  ngx.log(ngx.ERR, "no cookie in introspection call")
                end
                ngx.header.content_type = 'application/json;charset=UTF-8'
                test_globals.delay(REVOCATION_DELAY_RESPONSE)
                ngx.status = 200
                ngx.say('INVALID JSON.')
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
    elseif type(v) == "table" then
      t1[k] = {}
      merge(t1[k], v)
    else
      t1[k] = v
    end
  end
  return t1
end

local DEFAULT_INTROSPECTION_RESPONSE = merge({active=true}, DEFAULT_ACCESS_TOKEN)

local function write_template(out, template, custom_config)
  custom_config = custom_config or {}
  local oidc_config = merge(merge({}, DEFAULT_OIDC_CONFIG), custom_config["oidc_opts"] or {})
  local id_token = merge(merge({}, DEFAULT_ID_TOKEN), custom_config["id_token"] or {})
  local refresh_id_token = merge({}, id_token)
  local verify_opts = merge(merge({}, DEFAULT_VERIFY_OPTS), custom_config["verify_opts"] or {})
  local access_token = merge(merge({}, DEFAULT_ACCESS_TOKEN), custom_config["access_token"] or {})
  local token_header = merge(merge({}, DEFAULT_TOKEN_HEADER), custom_config["token_header"] or {})
  local userinfo = merge(merge({}, DEFAULT_ID_TOKEN), custom_config["userinfo"] or {})
  local introspection_response = merge(merge({}, DEFAULT_INTROSPECTION_RESPONSE),
                                       custom_config["introspection_response"] or {})
  local introspection_opts = merge(merge({}, DEFAULT_INTROSPECTION_OPTS),
                                   custom_config["introspection_opts"] or {})
  local token_response_expires_in = custom_config["token_response_expires_in"] or DEFAULT_TOKEN_RESPONSE_EXPIRES_IN
  local token_response_contains_refresh_token = custom_config["token_response_contains_refresh_token"]
    or DEFAULT_TOKEN_RESPONSE_CONTAINS_REFRESH_TOKEN
  local refreshing_token_fails = custom_config["refreshing_token_fails"] or DEFAULT_REFRESHING_TOKEN_FAILS
  local refresh_response_contains_id_token = custom_config["refresh_response_contains_id_token"] or DEFAULT_REFRESH_RESPONSE_CONTAINS_ID_TOKEN
  local access_token_opts = merge(merge({}, DEFAULT_OIDC_CONFIG), custom_config["access_token_opts"] or {})
  for _, k in ipairs(custom_config["remove_id_token_claims"] or {}) do
    id_token[k] = nil
  end
  for _, k in ipairs(custom_config["remove_refresh_id_token_claims"] or {}) do
    refresh_id_token[k] = nil
  end
  for _, k in ipairs(custom_config["remove_access_token_claims"] or {}) do
    access_token[k] = nil
  end
  for _, k in ipairs(custom_config["remove_userinfo_claims"] or {}) do
    userinfo[k] = nil
  end
  for _, k in ipairs(custom_config["remove_introspection_claims"] or {}) do
    introspection_response[k] = nil
  end
  for _, k in ipairs(custom_config["remove_oidc_config_keys"] or {}) do
    oidc_config[k] = nil
  end
  for _, k in ipairs(custom_config["remove_introspection_config_keys"] or {}) do
    introspection_opts[k] = nil
  end
  local content = template
    :gsub("OIDC_CONFIG", serpent.block(oidc_config, {comment = false }))
    :gsub("TOKEN_HEADER", serpent.block(token_header, {comment = false }))
    :gsub("JWT_SIGN_SECRET", custom_config["jwt_sign_secret"] or DEFAULT_JWT_SIGN_SECRET)
    :gsub("VERIFY_OPTS", serpent.block(verify_opts, {comment = false }))
    :gsub("INTROSPECTION_RESPONSE", serpent.block(introspection_response, {comment = false }))
    :gsub("INTROSPECTION_OPTS", serpent.block(introspection_opts, {comment = false }))
    :gsub("TOKEN_RESPONSE_EXPIRES_IN", token_response_expires_in)
    :gsub("TOKEN_RESPONSE_CONTAINS_REFRESH_TOKEN", token_response_contains_refresh_token)
    :gsub("REFRESHING_TOKEN_FAILS", refreshing_token_fails)
    :gsub("REFRESH_RESPONSE_CONTAINS_ID_TOKEN", refresh_response_contains_id_token)
    :gsub("ACCESS_TOKEN_OPTS", serpent.block(access_token_opts, {comment = false }))
    :gsub("JWK_DELAY_RESPONSE", ((custom_config["delay_response"] or {}).jwk or DEFAULT_DELAY_RESPONSE))
    :gsub("TOKEN_DELAY_RESPONSE", ((custom_config["delay_response"] or {}).token or DEFAULT_DELAY_RESPONSE))
    :gsub("DISCOVERY_DELAY_RESPONSE", ((custom_config["delay_response"] or {}).discovery or DEFAULT_DELAY_RESPONSE))
    :gsub("USERINFO_DELAY_RESPONSE", ((custom_config["delay_response"] or {}).userinfo or DEFAULT_DELAY_RESPONSE))
    :gsub("INTROSPECTION_DELAY_RESPONSE", ((custom_config["delay_response"] or {}).introspection or DEFAULT_DELAY_RESPONSE))
    :gsub("REVOCATION_DELAY_RESPONSE", ((custom_config["delay_response"] or {}).revocation or DEFAULT_DELAY_RESPONSE))
    :gsub("JWK", custom_config["jwk"] or DEFAULT_JWK)
    :gsub("USERINFO", serpent.block(userinfo, {comment = false }))
    :gsub("FAKE_ACCESS_TOKEN_SIGNATURE", custom_config["fake_access_token_signature"] or DEFAULT_FAKE_ACCESS_TOKEN_SIGNATURE)
    :gsub("FAKE_ID_TOKEN_SIGNATURE", custom_config["fake_id_token_signature"] or DEFAULT_FAKE_ID_TOKEN_SIGNATURE)
    :gsub("BREAK_ID_TOKEN_SIGNATURE", custom_config["break_id_token_signature"] or DEFAULT_BREAK_ID_TOKEN_SIGNATURE)
    :gsub("NONE_ALG_ID_TOKEN_SIGNATURE", custom_config["none_alg_id_token_signature"] or DEFAULT_NONE_ALG_ID_TOKEN_SIGNATURE)
    :gsub("REFRESH_ID_TOKEN", serpent.block(refresh_id_token, {comment = false }))
    :gsub("ID_TOKEN", serpent.block(id_token, {comment = false }))
    :gsub("ACCESS_TOKEN", serpent.block(access_token, {comment = false }))
    :gsub("UNAUTH_ACTION", custom_config["unauth_action"] and ('"' .. custom_config["unauth_action"] .. '"') or DEFAULT_UNAUTH_ACTION)
  out:write(content)
end

-- starts a server instance with some customizations of the configuration.
-- expects custom_config to be a table with:
-- - oidc_opts is a table containing options that are accepted by oidc.authenticate
-- - remove_oidc_config_keys is an array of keys to remove from the oidc configuration
-- - id_token is a table containing id_token claims
-- - remove_id_token_claims is an array of claims to remove from the id_token
-- - verify_opts is a table containing options that are accepted by oidc.bearer_jwt_verify
-- - jwt_signature_alg algorithm to use for signing JWTs
-- - jwt_sign_secret the secret to use when signing JWTs
-- - access_token is a table containing claims for the access token provided by /jwt
-- - token_header is a table containing claims for the header used by /jwt
--   as well as the id token
-- - remove_access_token_claims is an array of claims to remove from the access_token
-- - jwk the JWK keystore to provide
-- - userinfo is a table containing claims returned by the userinfo endpoint
-- - remove_userinfo_claims is an array of claims to remove from the userinfo response
-- - introspection_response is a table containing claims returned by
--   the introspection endpoint
-- - remove_introspection_claims is an array of claims to remove from the introspection response
-- - introspection_opts is a table containing options that are accepted by oidc.introspect
-- - remove_introspection_config_keys is an array of claims to remove from the introspection
--   configuration
-- - token_response_expires_in value for the expires_in claim of the token response
-- - token_response_contains_refresh_token whether to include a
--   refresh token with the token response (a boolean in quotes, i.e. "true" or "false")
-- - access_token_opts is a table containing options that are accepted by oidc.access_token
-- - delay_response is a table specifying a delay for the response of various endpoint in ms
--   { jwk = 1, token = 1, discovery = 1, userinfo = 1, introspection = 1}
-- - refreshing_token_fails whether to grant an access token via the refresh token grant
-- - fake_access_token_signature whether to fake a JWT signature with unknown algorithm for the
--   JWT returned by /jwt
-- - fake_id_token_signature whether to fake a JWT signature with unknown algorithm for the
--   id_token
-- - unauth_action value to pass as unauth_action parameter to authenticate
-- - break_id_token_signature whether to create an id token with an invalid signature
-- - none_alg_id_token_signature whether to use the "none" alg when signing the id token
function test_support.start_server(custom_config)
  assert(os.execute("rm -rf /tmp/server"), "failed to remove old server dir")
  assert(os.execute("mkdir -p /tmp/server/conf"), "failed to create server dir")
  assert(os.execute("mkdir -p /tmp/server/logs"), "failed to create log dir")
  local out = assert(io.open("/tmp/server/conf/test_globals.lua", "w"))
  write_template(out, DEFAULT_INIT_TEMPLATE, custom_config)
  assert(out:close())
  out = assert(io.open("/tmp/server/conf/nginx.conf", "w"))
  write_template(out, DEFAULT_CONFIG_TEMPLATE, custom_config)
  assert(out:close())
  assert(os.execute("openresty -c /tmp/server/conf/nginx.conf > /dev/null"), "failed to start nginx")
end

local function kill(pid, signal)
  if not signal then
    signal = ""
  else
    signal = "-" .. signal .. " "
  end
  return os.execute("/bin/sh -c '/bin/kill " .. signal .. pid .. "' 2>/dev/null")
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
   local h = headers or {}
   local pair = h["set-cookie"] or ''
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
