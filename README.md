[![Build Status](https://travis-ci.org/pingidentity/lua-resty-openidc.svg?branch=master)](https://travis-ci.org/pingidentity/lua-resty-openidc)

# lua-resty-openidc

**lua-resty-openidc** is a library for [NGINX](http://nginx.org/) implementing the
[OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html) **Relying Party (RP)**
and/or the [OAuth 2.0](https://tools.ietf.org/html/rfc6749) **Resource Server (RS)** functionality.

When used as an OpenID Connect Relying Party it authenticates users against an OpenID Connect
Provider using [OpenID Connect Discovery](http://openid.net/specs/openid-connect-discovery-1_0.html)
and the Basic Client Profile (i.e. the Authorization Code flow). When used as an OAuth 2.0
Resource Server it can validate OAuth 2.0 Bearer Access Tokens against an Authorization Server or, in
case a JSON Web Token is used for an Access Token, verification can happen against a pre-configured secret/key .

It maintains sessions for authenticated users by leveraging `lua-resty-session` thus offering
a configurable choice between storing the session state in a client-side browser cookie or use
in of the server-side storage mechanisms `shared-memory|memcache|redis`.

It supports server-wide caching of resolved Discovery documents and validated Access Tokens.

It can be used as a reverse proxy terminating OAuth/OpenID Connect in front of an origin server so that
the origin server/services can be protected with the relevant standards without implementing those on
the server itself.

## Dependencies

**lua-resty-openidc** depends on the following packages:

- [NGINX](http://nginx.org/) and [`ngx_devel_kit`](https://github.com/simpl/ngx_devel_kit)
- [Lua](http://www.lua.org/) or [LuaJIT](http://luajit.org/luajit.html)
- [`lua-nginx-module`](https://github.com/openresty/lua-nginx-module)
- [`lua-cjson`](http://www.kyne.com.au/~mark/software/lua-cjson.php)
- [`lua-resty-string`](https://github.com/openresty/lua-resty-string)

The dependencies above come automatically with [OpenResty](http://openresty.org/). You will need
to install two extra pure-Lua dependencies that implement session management and HTTP client functions:

- [`lua-resty-http`](https://github.com/pintsized/lua-resty-http)
- [`lua-resty-session`](https://github.com/bungle/lua-resty-session)

If you run as an OAuth 2.0 Resource Server and your access tokens are JWT bearer tokens and you want to
verify those tokens locally (no external callouts required, see 2nd configuration example below), you need
to install two more pure-Lua dependencies:

- [`lua-resty-jwt`](https://github.com/SkyLothar/lua-resty-jwt)
- [`lua-resty-hmac`](https://github.com/jkeys089/lua-resty-hmac)

## Installation

If you're using `luarocks` execute the following:

     luarocks install lua-resty-openidc

Otherwise copy `openidc.lua` somewhere in your `lua_package_path` under a directory named `resty`.
If you are using [OpenResty](http://openresty.org/), the default location would be `/usr/local/openresty/lualib/resty`.


## Sample Configuration for Google+ Signin

Sample `nginx.conf` configuration for authenticating users against Google+ Signin, protecting a reverse-proxied path.

```
events {
  worker_connections 128;
}

http {

  lua_package_path '~/lua/?.lua;;';

  resolver 8.8.8.8;

  lua_ssl_trusted_certificate /opt/local/etc/openssl/cert.pem;
  lua_ssl_verify_depth 5;

  # cache for discovery metadata documents
  lua_shared_dict discovery 1m;

  # NB: if you have "lua_code_cache off;", use:
  # set $session_secret xxxxxxxxxxxxxxxxxxx;
  # see: https://github.com/bungle/lua-resty-session#notes-about-turning-lua-code-cache-off
  
  server {
    listen 8080;

    location / {

      access_by_lua '

          local opts = {
             -- the full redirect URI must be protected by this script and becomes:
             -- ngx.var.scheme.."://"..ngx.var.http_host..opts.redirect_uri_path
             -- unless the scheme is overridden using opts.redirect_uri_scheme or an X-Forwarded-Proto header in the incoming request
             redirect_uri_path = "/redirect_uri",
             discovery = "https://accounts.google.com/.well-known/openid-configuration",
             client_id = "<client_id>",
             client_secret = "<client_secret>"
             --authorization_params = { hd="pingidentity.com" },
             --scope = "openid email profile",
             -- Refresh the user's id_token after 900 seconds without requiring re-authentication
             --refresh_session_interval = 900,
             --iat_slack = 600,
             --redirect_uri_scheme = "https",
             --logout_path = "/logout",
             --redirect_after_logout_uri = "/",
             --redirect_after_logout_with_id_token_hint = true,
             --token_endpoint_auth_method = ["client_secret_basic"|"client_secret_post"],
             --ssl_verify = "no"
             --access_token_expires_in = 3600
             -- Default lifetime in seconds of the access_token if no expires_in attribute is present in the token 
                endpoint response.
                This plugin will silently renew the access_token once it's expired if refreshToken scope is present.
             --access_token_expires_leeway = 0
                Expiration leeway for access_token renewal.
                If this is set, renewal will happen access_token_expires_leeway seconds before the token expiration.
                This avoids errors in case the access_token just expires when arriving to the OAuth Resoource Server.
             --force_reauthorize = false
             -- when force_reauthorize is set to true the authorization flow will be executed even if a token has been cached already
          }

          -- call authenticate for OpenID Connect user authentication
          local res, err = require("resty.openidc").authenticate(opts)

          if err then
            ngx.status = 500
            ngx.say(err)
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
          end

          -- at this point res is a Lua table with 3 keys:
          --   id_token    : a Lua table with the claims from the id_token (required)
          --   access_token: the access token (optional)
          --   user        : a Lua table with the claims returned from the user info endpoint (optional)

          --if res.id_token.hd ~= "pingidentity.com" then
          --  ngx.exit(ngx.HTTP_FORBIDDEN)
          --end

          --if res.user.email ~= "hans.zandbelt@zmartzone.eu" then
          --  ngx.exit(ngx.HTTP_FORBIDDEN)
          --end

          -- set headers with user info: this will overwrite any existing headers
          -- but also scrub(!) them in case no value is provided in the token
          ngx.req.set_header("X-USER", res.id_token.sub)
      ';

      proxy_pass http://localhost:80;
    }
  }
}
```

## Check authentication only

```
-- check session, but do not redirect to auth if not already logged in
local res, err = require("resty.openidc").authenticate(opts, nil, "pass")
```

## Sample Configuration for OAuth 2.0 JWT Token Validation

Sample `nginx.conf` configuration for verifying Bearer JWT Access Tokens against a pre-configured secret/key.
Once successfully verified, the NGINX server may function as a reverse proxy to an internal origin server.

```
events {
  worker_connections 128;
}

http {

  lua_package_path '~/lua/?.lua;;';

  resolver 8.8.8.8;

  # cache for JWT verification results
  lua_shared_dict introspection 10m;

  server {
    listen 8080;

    location /api {

      access_by_lua '

          local opts = {

            -- 1. example of a shared secret for HS??? signature verification
            --secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",

            -- 2. another example of a public cert for RS??? signature verification
            secret = [[-----BEGIN CERTIFICATE-----
MIIC0DCCAbigAwIBAgIGAVSbMZs1MA0GCSqGSIb3DQEBCwUAMCkxCzAJBgNVBAYTAlVTMQwwCgYD
VQQKEwNibGExDDAKBgNVBAMTA2JsYTAeFw0xNjA1MTAxNTAzMjBaFw0yNjA1MDgxNTAzMjBaMCkx
CzAJBgNVBAYTAlVTMQwwCgYDVQQKEwNibGExDDAKBgNVBAMTA2JsYTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAIcLtHjX2GFxYv1033dvfohyCU6nsuR1qoDXfHTG3Mf/Yj4BfLHtMjJr
nR3sgHItH3B6qZPnfErfsN0LP4uZ10/74CrWVqT5dy6ecXMqYtz/KNJ8rG0vY8vltc417AU4fie8
gyeWv/Z6wHWUCf3NHRV8GfFgfuvywgUpHo8ujpUPFr+zrPr8butrzJPq1h3+r0f5P45tfWOdpjCT
gsTzK6urUG0k3WkwdDYapL3wRCAw597nYfgKzzXuh9N0ZL3Uj+eJ6BgCzUZDLXABpMBZfk6hmmzp
cAFV4nTf1AaAs/EOwVE0YgZBJiBrueMcteAIxKrKjEHgThU2Zs9gN9cSFicCAwEAATANBgkqhkiG
9w0BAQsFAAOCAQEAQLU1A58TrSwrEccCIy0wxiGdCwQbaNMohzirc41zRMCXleJXbtsn1vv85J6A
RmejeH5f/JbDqRRRArGMdLooGbqjWG/lwZT456Q6DXqF2plkBvh37kp/GjthGyR8ODJn5ekZwxuB
OcTuruRhqYOIJjiYZSgK/P0zUw1cjLwUJ9ig/O6ozYmof83974fygA/wK3SgFNEoFlTkTpOvZhVW
9kLfCVA/CRBfJNKnz5PWBBxd/3XSEuP/fcWqKGTy7zZso4MTB0NKgWO4duGTgMyZbM4onJPyA0CY
lAc5Csj0o5Q+oEhPUAVBIF07m4rd0OvAVPOCQ2NJhQSL1oWASbf+fg==
-----END CERTIFICATE-----]],

            -- 3. alternatively one can point to a so-called Discovery document that
            -- contains "jwks_uri" entry; the jwks endpoint must provide a x5c entry
            -- discovery = "https://accounts.google.com/.well-known/openid-configuration",
          }

          -- call bearer_jwt_verify for OAuth 2.0 JWT validation
          local res, err = require("resty.openidc").bearer_jwt_verify(opts)

           if err or not res then
            ngx.status = 403
            ngx.say(err and err or "no access_token provided")
            ngx.exit(ngx.HTTP_FORBIDDEN)
          end

          -- at this point res is a Lua table that represents the JSON
          -- payload in the JWT token

          --if res.scope ~= "edit" then
          --  ngx.exit(ngx.HTTP_FORBIDDEN)
          --end

          --if res.client_id ~= "ro_client" then
          --  ngx.exit(ngx.HTTP_FORBIDDEN)
          --end
      ';

       proxy_pass http://localhost:80;
    }
  }
}
```

## Sample Configuration for PingFederate OAuth 2.0

Sample `nginx.conf` configuration for validating Bearer Access Tokens against a PingFederate OAuth 2.0 Authorization Server.

```
events {
  worker_connections 128;
}

http {

  lua_package_path '~/lua/?.lua;;';

  resolver 8.8.8.8;

  lua_ssl_trusted_certificate /opt/local/etc/openssl/cert.pem;
  lua_ssl_verify_depth 5;

  # cache for validation results
  lua_shared_dict introspection 10m;

  server {
    listen 8080;

    location /api {

      access_by_lua '

          local opts = {
             introspection_endpoint="https://localhost:9031/as/introspect.oauth2",
             client_id="rs_client",
             client_secret="2Federate",
             ssl_verify = "no",

             -- Defaults to "exp" - Controls the TTL of the introspection cache
             -- https://tools.ietf.org/html/rfc7662#section-2.2
             -- introspection_expiry_claim = "exp"
          }

          -- call introspect for OAuth 2.0 Bearer Access Token validation
          local res, err = require("resty.openidc").introspect(opts)

          if err then
            ngx.status = 403
            ngx.say(err)
            ngx.exit(ngx.HTTP_FORBIDDEN)
          end

          -- at this point res is a Lua table that represents the JSON
          -- object returned from the introspection/validation endpoint

          --if res.scope ~= "edit" then
          --  ngx.exit(ngx.HTTP_FORBIDDEN)
          --end

          --if res.client_id ~= "ro_client" then
          --  ngx.exit(ngx.HTTP_FORBIDDEN)
          --end
      ';
    }
  }
}
```

## Support

See the Wiki pages with Frequently Asked Questions at:  
  https://github.com/pingidentity/lua-resty-openidc/wiki  
For commercial support and consultancy you can contact:  
  [info@zmartzone.eu](mailto:info@zmartzone.eu)  

Any questions/issues should go to issues tracker or the primary author
[hans.zandbelt@zmartzone.eu](mailto:hans.zandbelt@zmartzone.eu)

Disclaimer
----------

*This software is open sourced by Ping Identity but not supported commercially
by Ping Identity, see also the DISCLAIMER file in this directory. For commercial support
you can contact [ZmartZone IAM](https://www.zmartzone.eu) as described above.*
