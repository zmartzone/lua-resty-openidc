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
Copyright (C) 2015-2017 Ping Identity Corporation
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

@Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
--]]

local require = require
local cjson   = require "cjson"
local http    = require "resty.http"
local string  = string
local ipairs  = ipairs
local pairs   = pairs
local type    = type
local ngx     = ngx
local b64     = ngx.encode_base64
local unb64   = ngx.decode_base64

local openidc = {
  _VERSION = "1.3.2"
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
  local value
  local flags
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
  if not id_token.iat then
    ngx.log(ngx.ERR, "no \"iat\" claim found in id_token")
    return false
  end

  local slack=opts.iat_slack and opts.iat_slack or 120
  if id_token.iat < (ngx.time() - slack) then
    ngx.log(ngx.ERR, "token is not valid yet: id_token.iat=", id_token.iat, ", ngx.time()=", ngx.time())
    return false
  end

  -- check expiry timestamp
  if id_token.exp < ngx.time() then
    ngx.log(ngx.ERR, "token expired: id_token.exp=", id_token.exp, ", ngx.time()=", ngx.time())
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
local function openidc_authorize(opts, session, target_url)
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
    nonce=nonce,
    prompt=opts.prompt and opts.prompt or ""
  }

  -- merge any provided extra parameters
  if opts.authorization_params then
    for k,v in pairs(opts.authorization_params) do params[k] = v end
  end

  -- store state in the session
  session:start()
  session.data.original_url = target_url
  session.data.state = state
  session.data.nonce = nonce
  session.data.last_authenticated = ngx.time()
  session:save()

  -- redirect to the /authorization endpoint
  return ngx.redirect(opts.discovery.authorization_endpoint.."?"..ngx.encode_args(params))
end

-- parse the JSON result from a call to the OP
local function openidc_parse_json_response(response)

  local err
  local res

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
local function openidc_call_token_endpoint(opts, endpoint, body, auth)

  local headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded"
  }

  if auth then
    if auth == "client_secret_basic" then
      headers.Authorization = "Basic "..ngx.encode_base64( opts.client_id..":"..opts.client_secret)
      ngx.log(ngx.DEBUG,"client_secret_basic: authorization header '"..headers.Authorization.."'")
    end
    if auth == "client_secret_post" then
      body.client_id=opts.client_id
      body.client_secret=opts.client_secret
      ngx.log(ngx.DEBUG, "client_secret_post: client_id and client_secret being sent in POST body")
    end
  end

  ngx.log(ngx.DEBUG, "request body for token endpoint call: ", ngx.encode_args(body))

  local httpc = http.new()
  local res, err = httpc:request_uri(endpoint, {
    method = "POST",
    body = ngx.encode_args(body),
    headers = headers,
    ssl_verify = (opts.ssl_verify ~= "no")
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
  if not opts.discovery.userinfo_endpoint then
    ngx.log(ngx.DEBUG, "no userinfo endpoint supplied")
    return nil, nil
  end

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

-- computes access_token expires_in value (in seconds)
local function openidc_access_token_expires_in(opts, expires_in)
  return (expires_in or opts.access_token_expires_in or 3600) - 1 - (opts.access_token_expires_leeway or 0)
end

-- handle a "code" authorization response from the OP
local function openidc_authorization_response(opts, session)
  local args = ngx.req.get_uri_args()
  local err

  if not args.code or not args.state then
    err = "unhandled request to the redirect_uri: "..ngx.var.request_uri
    ngx.log(ngx.ERR, err)
    return nil, err, session.data.original_url, session
  end

  -- check that the state returned in the response against the session; prevents CSRF
  if args.state ~= session.data.state then
    err = "state from argument: "..(args.state and args.state or "nil").." does not match state restored from session: "..(session.data.state and session.data.state or "nil")
    ngx.log(ngx.ERR, err)
    return nil, err, session.data.original_url, session
  end

  -- check the iss if returned from the OP
  if args.iss and args.iss ~= opts.discovery.issuer then
    err = "iss from argument: "..args.iss.." does not match expected issuer: "..opts.discovery.issuer
    ngx.log(ngx.ERR, err)
    return nil, err, session.data.original_url, session
  end

  -- check the client_id if returned from the OP
  if args.client_id and args.client_id ~= opts.client_id then
    err = "client_id from argument: "..args.client_id.." does not match expected client_id: "..opts.client_id
    ngx.log(ngx.ERR, err)
    return nil, err, session.data.original_url, session
  end

  -- assemble the parameters to the token endpoint
  local body = {
    grant_type="authorization_code",
    code=args.code,
    redirect_uri=openidc_get_redirect_uri(opts),
    state = session.data.state
  }

  local current_time = ngx.time()
  -- make the call to the token endpoint
  local json, err = openidc_call_token_endpoint(opts, opts.discovery.token_endpoint, body, opts.token_endpoint_auth_method)
  if err then
    return nil, err, session.data.original_url, session
  end

  -- process the token endpoint response with the id_token and access_token
  local enc_hdr, enc_pay, enc_sign = string.match(json.id_token, '^(.+)%.(.+)%.(.+)$')
  local jwt = openidc_base64_url_decode(enc_pay)
  local id_token = cjson.decode(jwt)

  -- validate the id_token contents
  if openidc_validate_id_token(opts, id_token, session.data.nonce) == false then
    err = "id_token validation failed"
    return nil, err, session.data.original_url, session
  end

  -- call the user info endpoint
  -- TODO: should this error be checked?
  local user, err = openidc_call_userinfo_endpoint(opts, json.access_token)

  session:start()
  session.data.user = user
  session.data.id_token = id_token
  session.data.enc_id_token = json.id_token
  session.data.access_token = json.access_token
  session.data.access_token_expiration = current_time
          + openidc_access_token_expires_in(opts, json.expires_in)
  if json.refresh_token ~= nil then
    session.data.refresh_token = json.refresh_token
  end

  -- save the session with the obtained id_token
  session:save()

  -- redirect to the URL that was accessed originally
  return ngx.redirect(session.data.original_url), session

end

-- get the Discovery metadata from the specified URL
local function openidc_discover(url, ssl_verify)
  ngx.log(ngx.DEBUG, "In openidc_discover - URL is "..url)

  local json, err
  local v = openidc_cache_get("discovery", url)
  if not v then

    ngx.log(ngx.DEBUG, "Discovery data not in cache. Making call to discovery endpoint")
    -- make the call to the discovery endpoint
    local httpc = http.new()
    local res, error = httpc:request_uri(url, {
      ssl_verify = (ssl_verify ~= "no")
    })
    if not res then
      err = "accessing discovery url ("..url..") failed: "..error
      ngx.log(ngx.ERR, err)
    else
      ngx.log(ngx.DEBUG, "Response data: "..res.body)
      json, err = openidc_parse_json_response(res)
      if json then
        if string.sub(url, 1, string.len(json['issuer'])) == json['issuer'] then
          openidc_cache_set("discovery", url, cjson.encode(json), 24 * 60 * 60)
        else
          err = "issuer field in Discovery data does not match URL"
          json = nil
        end
      else
        err = "could not decode JSON from Discovery data"
      end
    end

  else
    json = cjson.decode(v)
  end

  return json, err
end

local function openidc_jwks(url, ssl_verify)
  ngx.log(ngx.DEBUG, "In openidc_jwks - URL is "..url)

  local json, err
  local v = openidc_cache_get("jwks", url)
  if not v then

    ngx.log(ngx.DEBUG, "JWKS data not in cache. Making call to jwks endpoint")
    -- make the call to the jwks endpoint
    local httpc = http.new()
    local res, error = httpc:request_uri(url, {
      ssl_verify = (ssl_verify ~= "no")
    })
    if not res then
      err = "accessing jwks url ("..url..") failed: "..error
      ngx.log(ngx.ERR, err)
    else
      ngx.log(ngx.DEBUG, "Response data: "..res.body)
      json, err = openidc_parse_json_response(res)
      if json then
        openidc_cache_set("jwks", url, cjson.encode(json), 24 * 60 * 60)
      end
    end

  else
    json = cjson.decode(v)
  end

  return json, err
end

local function split_by_chunk(text, chunkSize)
  local s = {}
  for i=1, #text, chunkSize do
    s[#s+1] = text:sub(i,i+chunkSize - 1)
  end
  return s
end

local function get_jwk (keys, kid)
  for _, value in pairs(keys) do
    if value.kid == kid then
      return value
    end
  end

  return nil
end

-- Base64url decode
local b64map = { ['-'] = '+', ['_'] = '/' };
local function unb64url(s)
    return (unb64(s:gsub("[-_]", b64map) .. "=="));
end

local wrap = ('.'):rep(64);

local envelope = "-----BEGIN %s-----\n%s\n-----END %s-----\n"

local function der2pem(data, header, typ)  
    typ = typ:upper() or "CERTIFICATE";
  if header == nil then    
    data = b64(data);
    return string.format(envelope, typ, data:gsub(wrap, '%0\n', (#data-1)/64), typ);
  else 
    -- ADDING b64 RSA HEADER WITH OID 
    data = header .. b64(data)
    return string.format(envelope, typ,  data:gsub(wrap, '%0\n', (#data-1)/64), typ);
  end  
end


local function encode_length(length)
    if length < 0x80 then
        return string.char(length);
    elseif length < 0x100 then
        return string.char(0x81, length);
    elseif length < 0x10000 then
        return string.char(0x82, math.floor(length/0x100), length%0x100);
    end
    error("Can't encode lengths over 65535");
end


local function encode_sequence(array, of)
    local encoded_array = array;
    if of then
        encoded_array = {};
        for i = 1, #array do
            encoded_array[i] = of(array[i]);
        end
    end
    encoded_array = table.concat(encoded_array);
 
    return string.char(0x30) .. encode_length(#encoded_array) .. encoded_array;
end
 
local function encode_binary_integer(bytes)
    if bytes:byte(1) > 128 then
        -- We currenly only use this for unsigned integers,
        -- however since the high bit is set here, it would look
        -- like a negative signed int, so prefix with zeroes
        bytes = "\0" .. bytes;
     end
     return "\2" .. encode_length(#bytes) .. bytes;
end

local function encode_sequence_of_integer(array)
  return encode_sequence(array,encode_binary_integer);
end

local function encode_string(str, typ)
  if str:byte(1) > 128 then str = "\0" .. str; end
  return string.char(typ) .. encode_length(#str) .. str;
end

-- BIT STRING 0X03
-- OCTET STRING 0X04
local function encode_bit_string(str)
  return encode_string(str, 0x03);
end

local function pem_from_jwk (opts, kid)
  local cache_id = opts.discovery.jwks_uri .. '#' .. kid
  local v = openidc_cache_get("jwks", cache_id)

  if v then
    return v
  end

  local jwks, err = openidc_jwks(opts.discovery.jwks_uri, opts.ssl_verify)
  if err then
    return nil, err
  end

  local x5c = get_jwk(jwks.keys, kid).x5c
  -- TODO check x5c length
  local pem=""
  if x5c ~= nil then    
    ngx.log(ngx.DEBUG, "Found x5c, getting PEM public key from x5c entry of json public key")
    local chunks = split_by_chunk(ngx.encode_base64(openidc_base64_url_decode(x5c[1])), 64)
    pem = "-----BEGIN CERTIFICATE-----\n" .. table.concat(chunks, "\n") .. "\n-----END CERTIFICATE-----"    
    ngx.log(ngx.DEBUG,"Generated PEM key from x5c:",pem)
  else
    ngx.log(ngx.DEBUG , "x5c is nil, getting PEM public key from n and e parameters of json public key")

    --USE FIELD ORDER TO GENERATE PRIVATE KEY. NOT NEEDED FOR PUBLIC KEY 
    --RFC2313, OBJECT IDENTIFIER : http://www.oid-info.com/get/1.2.840.113549.1.1.1
   local algorithms = {
  RSA = {
    -- CONVERTED ASN.1 DOT NOTATION  1.2.840.113549.1.1.1 TO HEX AND THEN HEX TO ASCII AND ASCII TO DECIMAL TO GET THE BELOW STRING
    OID = "\006\009\042\134\072\134\247\013\001\001\001";     
    field_order = { 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi', };
    start = { "\0" };
    parameters = "\5\0";
  };
     };
 
  local kty = get_jwk(jwks.keys, kid).kty;
  local info = assert(algorithms[kty], "Unsupported key type");

  local der_key = {};
  local e = get_jwk(jwks.keys,kid).e;

  table.insert(der_key, unb64url(get_jwk(jwks.keys,kid).n));
  table.insert(der_key, unb64url(get_jwk(jwks.keys,kid).e));    

  local encoded_key = encode_sequence_of_integer(der_key);
  
  --PEM KEY FROM PUBLIC KEYS, PASSING 64 BIT ENCODED RSA HEADER STRING WHICH IS SAME FOR ALL KEYS
  local pem_key = der2pem(encoded_key,"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A","PUBLIC KEY")   
  ngx.log(ngx.DEBUG,"Generated pem key from n and e:",pem_key)
  pem = pem_key

  --ADDING RSA HEADER WITH OID, CURRENTLY NOT WORKING
  --local header = encode_sequence({ info.OID, info.parameters });
  -- SEQUENCE of above SEQUENCE, BIT STRING
  --local output = encode_sequence({ header, encode_bit_string(encoded_key) });
  --FINAL KEY WITH RSA HEADER
  --local final_key = der2pem(output, "PUBLIC KEY")) 
  end

  openidc_cache_set("jwks", cache_id, pem, 24 * 60 * 60)
  return pem
end

local openidc_transparent_pixel = "\137\080\078\071\013\010\026\010\000\000\000\013\073\072\068\082" ..
                                  "\000\000\000\001\000\000\000\001\008\004\000\000\000\181\028\012" ..
                                  "\002\000\000\000\011\073\068\065\084\120\156\099\250\207\000\000" ..
                                  "\002\007\001\002\154\028\049\113\000\000\000\000\073\069\078\068" ..
                                  "\174\066\096\130"

-- handle logout
local function openidc_logout(opts, session)
  local session_token = session.data.enc_id_token
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
  elseif opts.redirect_after_logout_uri and opts.redirect_after_logout_with_id_token_hint then
    return ngx.redirect(opts.redirect_after_logout_uri.."&id_token_hint="..session_token)
  elseif opts.redirect_after_logout_uri then
    return ngx.redirect(opts.redirect_after_logout_uri)
  elseif opts.discovery.end_session_endpoint then
    return ngx.redirect(opts.discovery.end_session_endpoint)
  elseif opts.discovery.ping_end_session_endpoint then
    return ngx.redirect(opts.discovery.ping_end_session_endpoint)
  end

  ngx.header.content_type = "text/html"
  ngx.say("<html><body>Logged Out</body></html>")
  ngx.exit(ngx.OK)
end

-- get the token endpoint authentication method
local function openidc_get_token_auth_method(opts)

  local result
  if opts.discovery.token_endpoint_auth_methods_supported ~= nil then
    -- if set check to make sure the discovery data includes the selected client auth method
    if opts.token_endpoint_auth_method ~= nil then
      for index, value in ipairs (opts.discovery.token_endpoint_auth_methods_supported) do
        ngx.log(ngx.DEBUG, index.." => "..value)
        if value == opts.token_endpoint_auth_method then
          ngx.log(ngx.DEBUG, "configured value for token_endpoint_auth_method ("..opts.token_endpoint_auth_method..") found in token_endpoint_auth_methods_supported in metadata")
          result = opts.token_endpoint_auth_method
          break
        end
      end
      if result == nil then
        ngx.log(ngx.ERR, "configured value for token_endpoint_auth_method ("..opts.token_endpoint_auth_method..") NOT found in token_endpoint_auth_methods_supported in metadata")
        return nil
      end
    else
      result = opts.discovery.token_endpoint_auth_methods_supported[1]
      ngx.log(ngx.DEBUG, "no configuration setting for option so select the first method specified by the OP: "..result)
    end
  else
    result = opts.token_endpoint_auth_method
  end

  -- set a sane default if auto-configuration failed
  if result == nil then
    result = "client_secret_basic"
  end

  ngx.log(ngx.DEBUG, "token_endpoint_auth_method result set to "..result)

  return result
end

-- returns a valid access_token (eventually refreshing the token)
local function openidc_access_token(opts, session)

  local err

  if session.data.access_token == nil then
    return nil, err
  end
  local current_time = ngx.time()
  if current_time < session.data.access_token_expiration then
    return session.data.access_token, err
  end
  if session.data.refresh_token == nil then
    return nil, err
  end

  ngx.log(ngx.DEBUG, "refreshing expired access_token: ", session.data.access_token, " with: ", session.data.refresh_token)

  -- retrieve token endpoint URL from discovery endpoint if necessary
  if type(opts.discovery) == "string" then
    opts.discovery, err = openidc_discover(opts.discovery, opts.ssl_verify)
    if err then
      return nil, err
    end
  end

  -- set the authentication method for the token endpoint
  opts.token_endpoint_auth_method = openidc_get_token_auth_method(opts)
  -- assemble the parameters to the token endpoint
  local body = {
    grant_type="refresh_token",
    refresh_token=session.data.refresh_token,
    scope=opts.scope and opts.scope or "openid email profile"
  }

  local json, err = openidc_call_token_endpoint(opts, opts.discovery.token_endpoint, body, opts.token_endpoint_auth_method)
  if err then
    return nil, err
  end
  ngx.log(ngx.DEBUG, "access_token refreshed: ", json.access_token, " updated refresh_token: ", json.refresh_token)

  session:start()
  session.data.access_token = json.access_token
  session.data.access_token_expiration = current_time + openidc_access_token_expires_in(opts, json.expires_in)
  if json.refresh_token ~= nil then
    session.data.refresh_token = json.refresh_token
  end

  -- save the session with the new access_token and optionally the new refresh_token
  session:save()

  return session.data.access_token, err

end

-- main routine for OpenID Connect user authentication
function openidc.authenticate(opts, target_url, unauth_action, session_opts)

  local err

  local session = require("resty.session").open(session_opts)

  local target_url = target_url or ngx.var.request_uri

  local access_token

  if type(opts.discovery) == "string" then
    --if session.data.discovery then
    --  opts.discovery = session.data.discovery
    --else
    --  session.data.discovery = opts.discovery
    --end
    opts.discovery, err = openidc_discover(opts.discovery, opts.ssl_verify)
    if err then
      return nil, err, target_url, session
    end
  end

  -- set the authentication method for the token endpoint
  opts.token_endpoint_auth_method = openidc_get_token_auth_method(opts)

  -- see if this is a request to the redirect_uri i.e. an authorization response
  local path = target_url:match("(.-)%?") or target_url
  if path == opts.redirect_uri_path then
    if not session.present then
      err = "request to the redirect_uri_path but there's no session state found"
      ngx.log(ngx.ERR, err)
      return nil, err, target_url, session
    end
    return openidc_authorization_response(opts, session), session
  end

  -- see if this is a request to logout
  if path == (opts.logout_path and opts.logout_path or "/logout") then
    return openidc_logout(opts, session), session
  end

  -- if we have no id_token then redirect to the OP for authentication
  if not session.present or not session.data.id_token or opts.force_reauthorize then
    if unauth_action == "pass" then
      return
        nil,
        err,
        target_url,
        session
    end
    return openidc_authorize(opts, session, target_url), session
  end

  -- silently reauthenticate if necessary (mainly used for session refresh/getting updated id_token data)
  if opts.refresh_session_interval ~= nil then
    if session.data.last_authenticated == nil or (session.data.last_authenticated+opts.refresh_session_interval) < ngx.time() then
      opts.prompt = "none"
      return openidc_authorize(opts, session, target_url), session
    end
  end

  -- refresh access_token if necessary
  access_token, err = openidc_access_token(opts, session)
  if err then
    return nil, err, target_url, session
  end

  -- log id_token contents
  ngx.log(ngx.DEBUG, "id_token=", cjson.encode(session.data.id_token))

  -- return the id_token to the caller Lua script for access control purposes
  return
    {
      id_token=session.data.id_token,
      access_token=access_token,
      user=session.data.user
    },
    err,
    target_url,
    session
end

-- get a valid access_token (eventually refreshing the token), or nil if there's no valid access_token
function openidc.access_token(opts, session_opts)

  local session = require("resty.session").open(session_opts)

  return openidc_access_token(opts, session)

end

-- get an OAuth 2.0 bearer access token from the HTTP request
local function openidc_get_bearer_access_token(opts)

  local err

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

  return access_token, err
end

-- main routine for OAuth 2.0 token introspection
function openidc.introspect(opts)

  -- get the access token from the request
  local access_token, err = openidc_get_bearer_access_token(opts)
  if access_token == nil then
    return nil, err
  end

  -- see if we've previously cached the introspection result for this access token
  local json
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
    json, err = openidc_call_token_endpoint(opts, opts.introspection_endpoint, body, nil)
    
    -- cache the results
    if json then
      if json.active then
        local expiry_claim = opts.expiry_claim or "expires_in"
        local ttl = json[expiry_claim]
        if expiry_claim ~= "exp" then --https://tools.ietf.org/html/rfc7662#section-2.2
          ttl = ttl - ngx.time()
        end
        openidc_cache_set("introspection", access_token, cjson.encode(json), ttl)
      else
        err = "invalid token"
      end
    end

  else
    json = cjson.decode(v)
  end

  return json, err
end

-- main routine for OAuth 2.0 JWT token validation
-- optional args are claim specs, see jwt-validators in resty.jwt
function openidc.jwt_verify(access_token, opts, ...)
  local err
  local json

  -- see if we've previously cached the validation result for this access token
  local v = openidc_cache_get("introspection", access_token)
  if not v then

    -- do the verification first time
    local jwt = require "resty.jwt"

    -- No secret given try getting it from the jwks endpoint
    if not opts.secret and opts.discovery then
      ngx.log(ngx.DEBUG, "bearer_jwt_verify using discovery.")
      if type(opts.discovery) == "string" then
        opts.discovery, err = openidc_discover(opts.discovery, opts.ssl_verify)
        if err then
          return nil, err
        end
      end

      -- We decode the token twice, could be saved
      local jwt_obj = jwt:load_jwt(access_token, nil)

      if not jwt_obj.valid then
        return nil, "invalid jwt"
      end

      opts.secret, err = pem_from_jwk(opts, jwt_obj.header.kid)

      if opts.secret == nil then
        return nil, err
      end
    end

    json = jwt:verify(opts.secret, access_token, ...)

    ngx.log(ngx.DEBUG, "jwt: ", cjson.encode(json))

    -- cache the results
    if json and json.valid == true and json.verified == true then
      json = json.payload
      openidc_cache_set("introspection", access_token, cjson.encode(json), json.exp - ngx.time())
    else
      err = "invalid token: ".. json.reason
    end

  else
    -- decode from the cache
    json = cjson.decode(v)
  end

  local slack=opts.iat_slack and opts.iat_slack or 120
  -- check the token expiry
  if json then
    if json.exp and json.exp + slack < ngx.time() then
      ngx.log(ngx.ERR, "token expired: json.exp=", json.exp, ", ngx.time()=", ngx.time())
      err = "JWT expired"
    end
  end

  return json, err
end

function openidc.bearer_jwt_verify(opts, ...)
  local err
  local json

  -- get the access token from the request
  local access_token, err = openidc_get_bearer_access_token(opts)
  if access_token == nil then
    return nil, err
  end

  ngx.log(ngx.DEBUG, "access_token: ", access_token)

  json, err = openidc.jwt_verify(access_token, opts, ...)
  return json, err, access_token
end

return openidc
