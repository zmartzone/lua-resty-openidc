--[[
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.

***************************************************************************
Copyright (C) 2015-2016 Ping Identity Corporation
All rights reserved.

For further information please contact:

     Ping Identity Corporation
     1099 18th St Suite 2950
     Denver, CO 80202
     303.468.2900
     http://www.pingidentity.com

DISCLAIMER OF WARRANTIES:

THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

@Author: Hans Zandbelt - hzandbelt@pingidentity.com
--]]

local cjson = require "cjson"
local http  = require "resty.http"

local openidc = {
  _VERSION = "1.0"
}
openidc.__index = openidc

-- set value in server-wide cache if available
local function openidc_cache_set(type, key, value, exp)
  local dict = ngx.shared[type]
  if dict then
    local success, err, forcible = dict:set(key, value, exp)
    ngx.log(ngx.DEBUG, "cache set: success=", success, " err=", err, " forcible=", forcible)
  end
end

-- retrieve value from server-wide cache if available
local function openidc_cache_get(type, key)
  local dict = ngx.shared[type]
  local value = nil
  local flags = nil
  if dict then
    value, flags = dict:get(key)
    if value then ngx.log(ngx.DEBUG, "cache hit: type=", type, " key=", key) end
  end
  return value
end

-- validate the contents of and id_token
local function openidc_validate_id_token(opts, id_token, nonce)

  -- check issuer
  if opts.discovery.issuer ~= id_token.iss then
    ngx.log(ngx.ERR, "issuer \"", id_token.iss, " in id_token is not equal to the issuer from the discovery document \"", opts.discovery.issuer, "\"")
    return false
  end

  -- check nonce
  if nonce and nonce ~= id_token.nonce then
    ngx.log(ngx.ERR, "nonce \"", id_token.nonce, " in id_token is not equal to the nonce that was sent in the request \"", nonce, "\"")
    return false
  end
 
  -- check issued-at timestamp
  local slack=opts.iat_slack and opts.iat_slack or 120
  if id_token.iat < (os.time() - slack) then
    ngx.log(ngx.ERR, "token is not valid yet: id_token.iat=", id_token.iat, ", os.time()=", os.time())
    return false
  end

  -- check expiry timestamp
  if id_token.exp < os.time() then
    ngx.log(ngx.ERR, "token expired: id_token.exp=", id_token.exp, ", os.time()=", os.time())
    return false
  end

  -- check audience (array or string)
  if (type(id_token.aud) == "table") then
    for key, value in pairs(id_token.aud) do
      if value == opts.client_id then
        return true
      end
    end
    ngx.log(ngx.ERR, "no match found token audience array: client_id=", opts.client_id )
    return false
  elseif  (type(id_token.aud) == "string") then
    if id_token.aud ~= opts.client_id then
      ngx.log(ngx.ERR, "token audience does not match: id_token.aud=", id_token.aud, ", client_id=", opts.client_id )
      return false
    end
  end
  return true
end

-- assemble the redirect_uri
local function openidc_get_redirect_uri(opts)
  local scheme = opts.redirect_uri_scheme or ngx.req.get_headers()['X-Forwarded-Proto'] or ngx.var.scheme
  return scheme.."://"..ngx.var.http_host..opts.redirect_uri_path
end

-- perform base64url decoding
local function openidc_base64_url_decode(input)
  local reminder = #input % 4
  if reminder > 0 then
    local padlen = 4 - reminder
    input = input .. string.rep('=', padlen)
  end
  input = input:gsub('-','+'):gsub('_','/')
  return ngx.decode_base64(input)
end

-- perform base64url encoding
local function openidc_base64_url_encode(input)
  input = ngx.encode_base64(input)
  return input:gsub('+','-'):gsub('/','_'):gsub('=','')
end

-- send the browser of to the OP's authorization endpoint
local function openidc_authorize(opts, session)
  local resty_random = require "resty.random"
  local resty_string = require "resty.string"

  -- generate state and nonce
  local state = resty_string.to_hex(resty_random.bytes(16))
  local nonce = resty_string.to_hex(resty_random.bytes(16))

  -- assemble the parameters to the authentication request
  local params = {
    client_id=opts.client_id,
    response_type="code",
    scope=opts.scope and opts.scope or "openid email profile",
    redirect_uri=openidc_get_redirect_uri(opts),
    state=state,
    nonce=nonce
  }

  -- merge any provided extra parameters
  if opts.authorization_params then
    for k,v in pairs(opts.authorization_params) do params[k] = v end
  end

  -- store state in the session
  session.data.original_url = ngx.var.uri
  session.data.state = state
  session.data.nonce = nonce
  session:save()

  -- redirect to the /authorization endpoint
  return ngx.redirect(opts.discovery.authorization_endpoint.."?"..ngx.encode_args(params))
end

-- parse the JSON result from a call to the OP
local function openidc_parse_json_response(response)

  local err = nil
  local res = nil

  -- check the response from the OP
  if response.status ~= 200 then
    err = "response indicates failure, status="..response.status..", body="..response.body
  else
    -- decode the response and extract the JSON object
    res = cjson.decode(response.body)

    if not res then
      err = "JSON decoding failed"
    end
  end

  return res, err
end

-- make a call to the token endpoint
local function openidc_call_token_endpoint(endpoint, body, ssl_verify)

  ngx.log(ngx.DEBUG, "request body for token endpoint call: ", ngx.encode_args(body))

  local httpc = http.new()
  local res, err = httpc:request_uri(endpoint, {
    method = "POST",
    body = ngx.encode_args(body),
    headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded",
    },
    ssl_verify = (ssl_verify ~= "no")
  })
  if not res then
    err = "accessing token endpoint ("..endpoint..") failed: "..err
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  ngx.log(ngx.DEBUG, "token endpoint response: ", res.body)

  return openidc_parse_json_response(res);
end

-- make a call to the userinfo endpoint
local function openidc_call_userinfo_endpoint(opts, access_token)

  local httpc = http.new()
  local res, err = httpc:request_uri(opts.discovery.userinfo_endpoint, {
    headers = {
      ["Authorization"] = "Bearer "..access_token,
    }
  })
  if not res then
    err = "accessing userinfo endpoint ("..opts.discovery.userinfo_endpoint..") failed: "..err
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  ngx.log(ngx.DEBUG, "userinfo response: ", res.body)

  -- parse the response from the user info endpoint
  return openidc_parse_json_response(res)
end

-- handle a "code" authorization response from the OP
local function openidc_authorization_response(opts, session)
  local args = ngx.req.get_uri_args()
  local err = nil

  if not args.code or not args.state then
    err = "unhandled request to the redirect_uri: "..ngx.var.request_uri
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  -- check that the state returned in the response against the session; prevents CSRF
  if args.state ~= session.data.state then
    err = "state from argument: "..(args.state and args.state or "nil").." does not match state restored from session: "..(session.data.state and session.data.state or "nil")
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  -- check the iss if returned from the OP
  if args.iss and args.iss ~= opts.discovery.issuer then
    err = "iss from argument: "..args.iss.." does not match expected issuer: "..opts.discovery.issuer
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  -- check the client_id if returned from the OP
  if args.client_id and args.client_id ~= opts.client_id then
    err = "client_id from argument: "..args.client_id.." does not match expected client_id: "..opts.client_id
    ngx.log(ngx.ERR, err)
    return nil, err
  end
    
  -- assemble the parameters to the token endpoint
  local body = {
    grant_type="authorization_code",
    client_id=opts.client_id,
    client_secret=opts.client_secret,
    code=args.code,
    redirect_uri=openidc_get_redirect_uri(opts),
    state = session.data.state
  }

  -- make the call to the token endpoint
  local json, err = openidc_call_token_endpoint(opts.discovery.token_endpoint, body, opts.ssl_verify)
  if err then
    return nil, err
  end

  -- process the token endpoint response with the id_token and access_token
  local enc_hdr, enc_pay, enc_sign = string.match(json.id_token, '^(.+)%.(.+)%.(.+)$')
  local jwt = openidc_base64_url_decode(enc_pay)
  session.data.id_token = cjson.decode(jwt)
  session.data.access_token = json.access_token

  -- validate the id_token contents
  if openidc_validate_id_token(opts, session.data.id_token, session.data.nonce) == false then
    err = "id_token validation failed"
    return nil, err
  end

  -- call the user info endpoint
  session.data.user, err = openidc_call_userinfo_endpoint(opts, json.access_token)

  -- save the session with the obtained id_token
  session:save()

  -- redirect to the URL that was accessed originally
  return ngx.redirect(session.data.original_url)

end

-- get the Discovery metadata from the specified URL
local function openidc_discover(url, ssl_verify)

  local err = nil
  local v = openidc_cache_get("discovery", url)
  if not v then

    -- make the call to the discovery endpoint
    local httpc = http.new()
    local res, error = httpc:request_uri(url, {
      ssl_verify = (ssl_verify ~= "no")
    })
    if not res then
      err = "accessing discovery url ("..url..") failed: "..error
      ngx.log(ngx.ERR, err)
    else
      json, err = openidc_parse_json_response(res)
      if json then
        openidc_cache_set("discovery", url, cjson.encode(json), 24 * 60 * 60)
      end
    end

  else
    json = cjson.decode(v)
  end

  return json, err
end

local openidc_transparent_pixel = "\137\080\078\071\013\010\026\010\000\000\000\013\073\072\068\082" ..
                                  "\000\000\000\001\000\000\000\001\008\004\000\000\000\181\028\012" ..
                                  "\002\000\000\000\011\073\068\065\084\120\156\099\250\207\000\000" .. 
                                  "\002\007\001\002\154\028\049\113\000\000\000\000\073\069\078\068" ..
                                  "\174\066\096\130"

-- handle logout
local function openidc_logout(opts, session)
  session:destroy()
  local headers = ngx.req.get_headers()
  local header =  headers['Accept']
  if header and header:find("image/png") then
    ngx.header["Cache-Control"] = "no-cache, no-store"
    ngx.header["Pragma"] = "no-cache"
    ngx.header["P3P"] = "CAO PSA OUR"
    ngx.header["Expires"] = "0"
    ngx.header["X-Frame-Options"] = "DENY"
    ngx.header.content_type = "image/png"
    ngx.print(openidc_transparent_pixel)
    ngx.exit(ngx.OK)
    return
  elseif opts.discovery.end_session_endpoint then
    return ngx.redirect(opts.discovery.end_session_endpoint)
  elseif opts.discovery.ping_end_session_endpoint then
    return ngx.redirect(opts.discovery.ping_end_session_endpoint)
  end
  
  ngx.header.content_type = "text/html"
  ngx.say("<html><body>Logged Out</body></html>")
  ngx.exit(ngx.OK)
end

-- main routine for OpenID Connect user authentication
function openidc.authenticate(opts)

  local err = nil

  local session = require("resty.session").start()

  if type(opts.discovery) == "string" then
    opts.discovery, err = openidc_discover(opts.discovery, opts.ssl_verify)
    if err then
      return nil, err
    end
  end

  -- see if this is a request to the redirect_uri i.e. an authorization response
  local path = ngx.var.request_uri
  path = path:match("(.-)%?") or path

  if path == opts.redirect_uri_path then
    return openidc_authorization_response(opts, session)
  end

  -- see if this is a request to logout
  if path == (opts.logout_path and opts.logout_path or "/logout") then
    return openidc_logout(opts, session)
  end

  -- if we have no id_token then redirect to the OP for authentication
  if not session.data.id_token then
    return openidc_authorize(opts, session)
  end

  -- log id_token contents
  ngx.log(ngx.DEBUG, "id_token=", cjson.encode(session.data.id_token))

  -- return the id_token to the caller Lua script for access control purposes
  return
    {
      id_token=session.data.id_token,
      access_token=session.data.access_token,
      user=session.data.user
    },
    err
end

-- main routine for OAuth 2.0 token introspection
function openidc.introspect(opts)

  local err = nil

  -- get the access token from the Authorization header
  local headers = ngx.req.get_headers()
  local header =  headers['Authorization']

  if header == nil or header:find(" ") == nil then
    err = "no Authorization header found"
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  local divider = header:find(' ')
  if string.lower(header:sub(0, divider-1)) ~= string.lower("Bearer") then
    err = "no Bearer authorization header value found"
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  local access_token = header:sub(divider+1)
  if access_token == nil then
    err = "no Bearer access token value found"
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  -- see if we've previously cached the introspection result for this access token
  local json = nil
  local v = openidc_cache_get("introspection", access_token)
  if not v then

    -- assemble the parameters to the introspection (token) endpoint
    local token_param_name = opts.introspection_token_param_name and opts.introspection_token_param_name or "access_token"

    local body = {}

    body[token_param_name]= access_token

    if opts.client_id then
      body.client_id=opts.client_id
    end
    if opts.client_secret then
      body.client_secret=opts.client_secret
    end

    -- merge any provided extra parameters
    if opts.introspection_params then
      for k,v in pairs(opts.introspection_params) do body[k] = v end
    end

    -- call the introspection endpoint
    json, err = openidc_call_token_endpoint(opts.introspection_endpoint, body, opts.ssl_verify)

    -- cache the results
    if json then
      openidc_cache_set("introspection", access_token, cjson.encode(json), json.expires_in)
    end

  else
    json = cjson.decode(v)
  end

  return json, err
end

return openidc
