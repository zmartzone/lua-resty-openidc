[![Build Status](https://travis-ci.org/zmartzone/lua-resty-openidc.svg?branch=master)](https://travis-ci.org/zmartzone/lua-resty-openidc)
[<img width="184" height="96" align="right" src="http://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm@2x.png" alt="OpenID Certification">](https://openid.net/certification)

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

Typically - when running as an OpenID Connect RP or an OAuth 2.0 server that consumes JWT
access tokens - you'll also need to install the following dependency:

- [`lua-resty-jwt`](https://github.com/cdbattags/lua-resty-jwt)

The `lua-resty-jwt` dependency above is *not* required when running as an OAuth 2.0 Resource Server (only) using remote
introspection for access token validation.

## Installation

If you're using `opm` execute the following:

     opm install zmartzone/lua-resty-openidc

If you're using `luarocks` execute the following:

     luarocks install lua-resty-openidc

Otherwise copy `openidc.lua` somewhere in your `lua_package_path` under a directory named `resty`.
If you are using [OpenResty](http://openresty.org/), the default location would be `/usr/local/openresty/lualib/resty`.


## Support

#### Community Support

For generic questions, see the Wiki pages with Frequently Asked Questions at:  
[https://github.com/zmartzone/lua-resty-openidc/wiki](https://github.com/zmartzone/lua-resty-openidc/wiki)  
Any questions/issues should go to issues tracker.

#### Commercial Services

For commercial Support contracts, Professional Services, Training and use-case specific support you can contact:  
[sales@zmartzone.eu](mailto:sales@zmartzone.eu)

## Sample Configuration for Google+ Signin

Sample `nginx.conf` configuration for authenticating users against Google+ Signin, protecting a reverse-proxied path.

```nginx
events {
  worker_connections 128;
}

http {

  lua_package_path '~/lua/?.lua;;';

  resolver 8.8.8.8;

  lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
  lua_ssl_verify_depth 5;

  # cache for discovery metadata documents
  lua_shared_dict discovery 1m;
  # cache for JWKs
  lua_shared_dict jwks 1m;

  # NB: if you have "lua_code_cache off;", use:
  # set $session_secret xxxxxxxxxxxxxxxxxxx;
  # see: https://github.com/bungle/lua-resty-session#notes-about-turning-lua-code-cache-off

  server {
    listen 8080;

    location / {

      access_by_lua_block {

          local opts = {
             -- the full redirect URI must be protected by this script
             -- if the URI starts with a / the full redirect URI becomes
             -- ngx.var.scheme.."://"..ngx.var.http_host..opts.redirect_uri
             -- unless the scheme was overridden using opts.redirect_uri_scheme or an X-Forwarded-Proto header in the incoming request
             redirect_uri = "https://MY_HOST_NAME/redirect_uri",
             -- up until version 1.6.1 you'd specify
             -- redirect_uri_path = "/redirect_uri",
             -- and could not set the hostname

             -- The discovery endpoint of the OP. Enable to get the URI of all endpoints (Token, introspection, logout...)
             discovery = "https://accounts.google.com/.well-known/openid-configuration",

             -- Access to OP Token endpoint requires an authentication. Several authentication modes are supported:
             --token_endpoint_auth_method = ["client_secret_basic"|"client_secret_post"|"private_key_jwt"|"client_secret_jwt"],
             -- o If token_endpoint_auth_method is set to "client_secret_basic", "client_secret_post", or "client_secret_jwt", authentication to Token endpoint is using client_id and client_secret
             --   For non compliant OPs to OAuth 2.0 RFC 6749 for client Authentication (cf. https://tools.ietf.org/html/rfc6749#section-2.3.1)
             --   client_id and client_secret MUST be invariant when url encoded
             client_id = "<client_id>",
             client_secret = "<client_secret>",
             -- o If token_endpoint_auth_method is set to "private_key_jwt" authentication to Token endpoint is using client_id, client_rsa_private_key and client_rsa_private_key_id to compute a signed JWT
             --   client_rsa_private_key is the RSA private key to be used to sign the JWT generated by lua-resty-openidc for authentication to the OP
             --   client_rsa_private_key_id (optional) is the key id to be set in the JWT header to identify which public key the OP shall use to verify the JWT signature
             --client_id = "<client_id>",
             --client_rsa_private_key=[[-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAiThmpvXBYdur716D2q7fYKirKxzZIU5QrkBGDvUOwg5izcTv
[...]
h2JHukolz9xf6qN61QMLSd83+kwoBr2drp6xg3eGDLIkQCQLrkY=
-----END RSA PRIVATE KEY-----]],
             --client_rsa_private_key_id="key id#1",
             --   Life duration expressed in seconds of the signed JWT generated by lua-resty-openidc for authentication to the OP.
             --   (used when token_endpoint_auth_method is set to "private_key_jwt" or "client_secret_jwt" authentication). Default is 60 seconds.
             --client_jwt_assertion_expires_in = 60,
             -- When using https to any OP endpoints, enforcement of SSL certificate check can be mandated ("yes") or not ("no").
             --ssl_verify = "no",
             -- Connection keepalive with the OP can be enabled ("yes") or disabled ("no").
             --keepalive = "no",

             --authorization_params = { hd="zmartzone.eu" },
             --scope = "openid email profile",
             -- Refresh the users id_token after 900 seconds without requiring re-authentication
             --refresh_session_interval = 900,
             --iat_slack = 600,
             --redirect_uri_scheme = "https",
             --logout_path = "/logout",
             --redirect_after_logout_uri = "/",
             -- Where should the user be redirected after logout from the RP. This option overides any end_session_endpoint that the OP may have provided in the discovery response.
             --redirect_after_logout_with_id_token_hint = true,
             -- Whether the redirection after logout should include the id token as an hint (if available). This option is used only if redirect_after_logout_uri is set.
             --post_logout_redirect_uri = "https://www.zmartzone.eu/logoutSuccessful",
             -- Where does the RP requests that the OP redirects the user after logout. If this option is set to a relative URI, it will be relative to the OP's logout endpoint, not the RP's.

             --accept_none_alg = false
             -- if your OpenID Connect Provider doesn't sign its id tokens
             -- (uses the "none" signature algorithm) then set this to true.

             --accept_unsupported_alg = true
             -- if you want to reject tokens signed using an algorithm
             -- not supported by lua-resty-jwt set this to false. If
             -- you leave it unset or set it to true, the token signature will not be
             -- verified when an unsupported algorithm is used.

             --renew_access_token_on_expiry = true
             -- whether this plugin shall try to silently renew the access token once it is expired if a refresh token is available.
             -- if it fails to renew the token, the user will be redirected to the authorization endpoint.
             --access_token_expires_in = 3600
             -- Default lifetime in seconds of the access_token if no expires_in attribute is present in the token endpoint response.

             --access_token_expires_leeway = 0
             --  Expiration leeway for access_token renewal. If this is set, renewal will happen access_token_expires_leeway seconds before the token expiration. This avoids errors in case the access_token just expires when arriving to the OAuth Resource Server.

             --force_reauthorize = false
             -- When force_reauthorize is set to true the authorization flow will be executed even if a token has been cached already. 
             -- If set, will override `reuse_existing_login_sessions` option.

             --session_contents = {id_token=true}
             -- Whitelist of session content to enable. This can be used to reduce the session size.
             -- When not set everything will be included in the session.
             -- Available are:
             -- id_token, enc_id_token, user, access_token (includes refresh token)

             -- You can specify timeouts for connect/send/read as a single number (setting all timeouts) or as a table. Values are in milliseconds
             -- timeout = 1000
             -- timeout = { connect = 500, send = 1000, read = 1000 }

             --use_nonce = false
             -- By default the authorization request includes the
             -- nonce parameter. You can use this option to disable it
             -- which may be necessary when talking to a broken OpenID
             -- Connect provider that ignores the parameter as the
             -- id_token will be rejected otherwise.

             --reuse_existing_login_sessions = true
             -- By default a new session and nonce is generated every time authorization is (re)started, invalidating previously open login tabs.
             -- However, an existing session can be reused so all the previously opened login tabs are valid
             -- Will be ignored when `force_reauthorize` option is set.

             --ignore_following_logins = true
             -- By default if user logins when already logged, this second login will throw an error because state/nonce we wiped by the first login
             -- By setting the parameter to true, following logins would be ignored and will redirect user to return url

             --revoke_tokens_on_logout = false
             -- When revoke_tokens_on_logout is set to true a logout notifies the authorization server that previously obtained refresh and access tokens are no longer needed. This requires that revocation_endpoint is discoverable.
             -- If there is no revocation endpoint supplied or if there are errors on revocation the user will not be notified and the logout process continues normally.

             -- Optional : use outgoing proxy to the OpenID Connect provider endpoints with the proxy_opts table :
             -- this requires lua-resty-http >= 0.12
             -- proxy_opts = {
             --    http_proxy  = "http://<proxy_host>:<proxy_port>/",
             --    https_proxy = "http://<proxy_host>:<proxy_port>/"
             -- }

             -- Lifecycle Hooks
             --
             -- lifecycle = {
             --    on_created = handle_created,
             --    on_authenticated = handle_authenticated,
             --    on_regenerated = handle_regenerated
             --    on_logout = handle_logout
             -- }
             --
             -- where `handle_created`, `handle_authenticated`, `handle_regenerated` and `handle_logout` are callables
             -- accepting a single argument `session`
             --
             --  -- `on_created` hook is invoked *after* a session has been created in
             --     `openidc_authorize` immediately prior to saving the session
             --  -- `on_authenticated` hook is invoked *after* receiving authorization response in
             --     `openidc_authorization_response` immediately prior to saving the session
             --  -- `on_regenerated` is invoked immediately after the
                     a new access token has been obtained via token
                     refresh and is called with the regenerated session table
             --  -- `on_logout` hook is invoked *before* a session is destroyed in
             --     `openidc_logout`
             --
             --  Any, all or none of the hooks may be used. Empty `lifecycle` does nothing.

             -- Optional : add decorator for HTTP request that is
             -- applied when lua-resty-openidc talks to the OpenID Connect
             -- provider directly. Can be used to provide extra HTTP headers
             -- or add other similar behavior.
             -- http_request_decorator = function(req)
             --   local h = req.headers or {}
             --   h[EXTRA_HEADER] = 'my extra header'
             --   req.headers = h
             --   return req
             -- end,

             -- use_pkce = false,
             -- when set to true the "Proof Key for Code Exchange" as
             -- defined in RFC 7636 will be used. The code challenge
             -- method will alwas be S256

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

          --if res.id_token.hd ~= "zmartzone.eu" then
          --  ngx.exit(ngx.HTTP_FORBIDDEN)
          --end

          --if res.user.email ~= "hans.zandbelt@zmartzone.eu" then
          --  ngx.exit(ngx.HTTP_FORBIDDEN)
          --end

          -- set headers with user info: this will overwrite any existing headers
          -- but also scrub(!) them in case no value is provided in the token
          ngx.req.set_header("X-USER", res.id_token.sub)
      }

      proxy_pass http://localhost:80;
    }
  }
}
```

## Check authentication only

```lua
-- check session, but do not redirect to auth if not already logged in
local res, err = require("resty.openidc").authenticate(opts, nil, "pass")
```

## Check authentication only and deny unauthenticated access

```lua
-- check session, do not redirect to auth if not already logged in but return an error instead
local res, err = require("resty.openidc").authenticate(opts, nil, "deny")
```

## Sessions and Locking

The `authenicate` function returns the current session object as its
forth return argument. If you have configured lua-resty-session to use
a server side storade backend that uses locking, the session may still
be locked when it is returned. In this case you may want to close it
explicitly

```lua
local res, err, target, session = require("resty.openidc").authenticate(opts)
session:close()
```

## Sample Configuration for OAuth 2.0 JWT Token Validation

Sample `nginx.conf` configuration for verifying Bearer JWT Access Tokens against a pre-configured secret/key.
Once successfully verified, the NGINX server may function as a reverse proxy to an internal origin server.

```nginx
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
            --symmetric_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            -- in versions up to 1.6.1 this option's key would have been secret
            -- rather than symmetric_key

            -- 2. another example of a public cert for RS??? signature verification
            public_key = [[-----BEGIN CERTIFICATE-----
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
            -- in versions up to 1.6.1 this option's key would have been secret
            -- rather than public_key

            -- 3. alternatively one can point to a so-called Discovery document that
            -- contains "jwks_uri" entry; the jwks endpoint must provide either an "x5c" entry
            -- or both the "n" modulus and "e" exponent entries for RSA signature verification
            -- discovery = "https://accounts.google.com/.well-known/openid-configuration",

             -- the signature algorithm that you expect has been used;
             -- can be a single string or a table.
             -- You should set this for security reasons in order to
             -- avoid accepting a token claiming to be signed by HMAC
             -- using a public RSA key.
             --token_signing_alg_values_expected = { "RS256" }

             -- if you want to accept unsigned tokens (using the
             -- "none" signature algorithm) then set this to true.
             --accept_none_alg = false

             -- if you want to reject tokens signed using an algorithm
             -- not supported by lua-resty-jwt set this to false. If
             -- you leave it unset, the token signature will not be
             -- verified at all.
             --accept_unsupported_alg = true

             -- the expiration time in seconds for jwk cache, default is 1 day.
             --jwk_expires_in = 24 * 60 * 60

          }

          -- call bearer_jwt_verify for OAuth 2.0 JWT validation
          local res, err = require("resty.openidc").bearer_jwt_verify(opts)

           if err or not res then
            ngx.status = 403
            ngx.say(err and err or "no access_token provided")
            ngx.exit(ngx.HTTP_FORBIDDEN)
          end

          -- at this point res is a Lua table that represents the (validated) JSON
          -- payload in the JWT token; now we typically do not want to allow just any
          -- token that was issued by the Authorization Server but we want to apply
          -- some access restrictions via client IDs or scopes

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

```nginx
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

## Sample Configuration for passing bearer OAuth 2.0 access tokens as cookie

Sample `nginx.conf` configuration for validating Bearer Access Tokens passed as cookie against a ORY/Hydra Authorization Server.

```nginx
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
             -- sets the URI of the introspection endpoint
             introspection_endpoint="https://localhost:9031/oauth2/introspect",

             -- alternatively if your OAuth2 Provider provides a discovery document that contains the
             -- introspection_endpoint claim you can leave the introspection_endpoint option
             -- unset and instead use
             -- discovery = "https://my-oauth2-provider/.well-known/oauth-authorization-server",

             client_id="admin",
             client_secret="demo-password",
             ssl_verify = "no",

             -- Defines the interval in seconds after which a cached and introspected access token needs
             -- to be refreshed by introspecting (and validating) it again against the Authorization Server.
             -- When not defined the value is 0, which means it only expires after the `exp` (or alternative,
             -- see introspection_expiry_claim) hint as returned by the Authorization Server
             -- introspection_interval = 60,

             -- Defines the way in which bearer OAuth 2.0 access tokens can be passed to this Resource Server.
             -- "cookie" as a cookie header called "PA.global" or using the name specified after ":"
             -- "header" "Authorization: bearer" header
             -- When not defined the default "Authorization: bearer" header is used
             -- auth_accept_token_as = "cookie:PA",

             -- If header is used header field is Authorization
             -- auth_accept_token_as_header_name = "cf-Access-Jwt-Assertion"

             -- Authentication method for the OAuth 2.0 Authorization Server introspection endpoint,
             -- Used to authenticate the client to the introspection endpoint with a client_id/client_secret
             -- Defaults to "client_secret_post"
             -- introspection_endpoint_auth_method = "client_secret_basic",

             -- Specify the names of cookies separated by whitespace to pickup from the browser and send along on backchannel
             -- calls to the OP and AS endpoints.
             -- When not defined, no such cookies are sent.
             -- pass_cookies = "JSESSION"

             -- Defaults to "exp" - Controls the TTL of the introspection cache
             -- https://tools.ietf.org/html/rfc7662#section-2.2
             -- introspection_expiry_claim = "exp"

             -- It may be necessary to force an introspection call for an access_token and ignore the existing cached
             -- introspection results. If so you need to set set the introspection_cache_ignore option to true.
             -- introspection_cache_ignore = true
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

## Logging

Logging can be customized, including using custom logger and remapping OpenIDC's
default log levels, e.g:

```lua
local openidc = require("resty.openidc")
openidc.set_logging(nil, { DEBUG = ngx.INFO })
```

## Running Tests

We've created a dockerized setup for the test in order to simplify the
installation of dependencies.

In order to run the tests perform

```shell
$ docker build -f tests/Dockerfile . -t lua-resty-openidc/test
$ docker run -it --rm lua-resty-openidc/test:latest
```

if you want to create
[luacov](https://keplerproject.github.io/luacov/) coverage while
testing use

```shell
$ docker run -it --rm -e coverage=t lua-resty-openidc/test:latest
```

as the second command

Disclaimer
----------

*This software is open sourced by ZmartZone IAM. For commercial support
you can contact [ZmartZone IAM](https://www.zmartzone.eu) as described above in the [Support](#support) section.*
