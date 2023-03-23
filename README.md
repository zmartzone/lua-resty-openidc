[![CI Status](https://github.com/zmartzone/lua-resty-openidc/actions/workflows/docker-ci.yml/badge.svg)](https://github.com/zmartzone/lua-resty-openidc/actions/workflows/docker-ci.yml)
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

Using `luarocks` execute the following:

     luarocks install lua-resty-openidc

Otherwise copy `openidc.lua` somewhere in your `lua_package_path` under a directory named `resty`.
If you are using [OpenResty](http://openresty.org/), the default location would be `/usr/local/openresty/lualib/resty`.

Older versions of lua-resty-openidc could also be installed using opm
but this is no longer supported.


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

             --response_mode=form_post can be used to make lua-resty-openidc use the [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html). *Note* for modern browsers you will need to set [`$session_cookie_samesite`](https://github.com/bungle/lua-resty-session#string-sessioncookiesamesite) to `None` with form_post unless your OpenID Connect Provider and Relying Party share the same domain.
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
             -- When force_reauthorize is set to true the authorization flow will be executed even if a token has been cached already
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
             -- nonce paramter. You can use this option to disable it
             -- which may be necessary when talking to a broken OpenID
             -- Connect provider that ignores the paramter as the
             -- id_token will be rejected otherwise.

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
             --     Starting with lua-resty-openidc 1.7.5 this receives the decoded id_token as second and the response of the token endpoint as third argument      
             --  -- `on_regenerated` is invoked immediately after the
                     a new access token has been obtained via token
                     refresh and is called with the regenerated session table
             --  -- `on_logout` hook is invoked *before* a session is destroyed in
             --     `openidc_logout`
             --
             --  Any, all or none of the hooks may be used. Empty `lifecycle` does nothing.
             --  A hook that returns a truthy value causes the lifecycle action they are taking part of to fail.

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

## About `redirect_uri`

The so called `redirect_uri` is an URI that is part of the OpenID
Connect protocoll. The redirect URI is registered with your OpenID
Connect provider and is the URI your provider will redirect the users
to after successful login. This URI then is handelled by
lua-resty-openidc where it obtains tokens and performs some checks and
only after that the browser is redirected to where your user wanted to
go initially.

The `redirect_uri` is not expected to be handelled by your appication
code at all. It must be an URI wthat lua-resty-openidc is responsible
for so it must be in a `location` protected by lua-resty-openidc.

You configure the `redirect_uri` on the lua-resty-openidc side via the
`opts.redirect_uri` parameter (which defaults to `/redirect_uri`). If
it starts with a `/` then lua-resty-openidc will prepend the protocoll
and current hostname to it when sending the URI to the OpenID Connect
provider (taking `Forwarded` and `X-Forwarded-*` HTTP headers into
account). But you can also specify an absolute URI containing host and
protocoll yourself.

Before version 1.6.1 `opts.redirect_uri_path` has been the way to
configure the `redirect_uri` without any option to take control over
the protocoll and host parts.

Whenever lua-resty-openidc "sees" a local path navigated that matches
the path of `opts.redirect_uri` (or `opts.redirect_uri_path`) it will
intercept the request and handle it itself.

This works for most cases but sometimes the externally visible
`redirect_uri` has a different path than the one locally visible to
the server. This may happen if a reverse proxy in front of your server
rewrites URIs before forwarding the requests. Therefore version 1.7.6
introduced a new option `opts.local_redirect_uri_path`. If it is set
lua-resty-opendic will intercepts requests to this path rather than
the path of `opts.redirect_uri`.


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

The `authenticate` function returns the current session object as its
forth return argument. If you have configured lua-resty-session to use
a server side storage backend that uses locking, the session may still
be locked when it is returned. In this case you may want to close it
explicitly

```lua
local res, err, target, session = require("resty.openidc").authenticate(opts)
session:close()
```

## Caching

lua-resty-openidc can use [shared memory
caches](https://github.com/openresty/lua-nginx-module/#lua_shared_dict)
for several things. If you want it to use the caches, you must use
`lua_shared_dict` in your `nginx.conf` file.

Currently up to four caches are used

* the cache named `discovery` stores the OpenID Connect Disovery
  metadata of your OpenID Connect Provider. Cache items expire after
  24 hours unless overriden by `opts.discovery_expires_in` (a value
  given in seconds) . This cache will store one item per issuer URI
  and you can look up the discovery document yourself to get an
  estimate for the size required - usually a few kB per OpenID Connect
  Provider.
* the cache named `jwks` stores the key material of your OpenID
  Connect Provider if it is provided via the JWKS endpoint. Cache
  items expire after 24 hours unless overriden by
  `opts.jwks_expires_in`. This cache will store one item per JWKS URI
  and you can look up the jwks yourself to get an estimate for the
  size required - usually a few kB per OpenID Connect Provider.
* the cache named `introspection` stores the result of OAuth2 token
  introspection. Cache items expire when the corresponding token
  expires. Tokens with unknown expiry are not cached at all. This
  cache will contain one entry per introspected access token - usually
  this will be a few kB per token.
* the cache named `jwt_verification` stores the result of JWT
  verification.  Cache items expire when the corresponding token
  expires. Tokens with unknown expiry are not cached for two
  minutes. This cache will contain one entry per verified JWT -
  usually this will be a few kB per token.

## Caching of Introspection and JWT Verification Results

Note the `jwt_verification` and `introspection` caches are shared
between all configured locations. If you are using locations with
different `opts` configuration the shared cache may allow a token that
is valid for only one location to be accepted by another if it is read
from the cache. In order to avoid cache confusion it is recommended to
set `opts.cache_segment` to unique strings for each set of related
locations.

## Revoke tokens

The `revoke_tokens(opts, session)` function revokes the current refresh and access token. In contrast to a full logout, the session cookie will not be destroyed and the endsession endpoint will not be called. The function returns `true` if both tokens were revoked successfully. This function might be helpful in scenarios where you want to destroy/remove a session from the server side.

With `revoke_token(opts, token_type_hint, token)` it is also possible to revoke a specific token. `token_type_hint` can usually be `refresh_token` or `access_token`.

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
  lua_shared_dict jwt_verification 10m;

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

             -- It may be necessary to force verification for a bearer token and ignore the existing cached
             -- verification results. If so you need to set set the jwt_verification_cache_ignore option to true.
             -- jwt_verification_cache_ignore = true

             -- optional name of a cache-segment if you need separate
             -- caches for differently configured locations
             -- cache_segment = 'api'
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

             -- optional name of a cache-segment if you need separate
             -- caches for differently configured locations
             -- cache_segment = 'api'
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

             -- optional name of a cache-segment if you need separate
             -- caches for differently configured locations
             -- cache_segment = 'api'
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

## Sample Configuration for Keycloak OpenID Connect authentication with encrypted tokens

Sample `nginx.conf` configuration to authenticate using OpenID Connect against a Keycloak 18.0 Authorization Server.
With this configuration, the authorization server returns encrypted tokens for each OIDC tokens.

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
  
  lua_package_cpath "/usr/local/include/lua/?.so;;";
  lua_package_path "/usr/local/openresty/luajit/share/lua/?.lua;/usr/local/lib/lua/?.lua;/usr/local/share/lua/5.1/?.lua;";
  lua_shared_dict discovery 1m;
  lua_shared_dict jwks 1m;

  server {
  	# General settings
        listen 443 ssl;
        root /var/www/html;
        resolver 127.0.0.1:5353;
        
        # Logs settings
        access_log /etc/nginx/log/app-access.log;
        error_log /etc/nginx/log/app-error.log;

        # SSL Settings
        ssl_certificate /etc/nginx/keys/tls.crt;
        ssl_certificate_key /etc/nginx/keys/tls.key;
        ssl_verify_depth 2;
        ssl_trusted_certificate /etc/nginx/ca/caBundle.crt;

        location = /favicon.ico {
            log_not_found off;
        }

	# Publish a statically generated JWKS to be used by the OP
        location /public/jwks.json {
            alias /etc/nginx/public/jwks.json;
            
        }

        location /secure {
            access_by_lua_block {
                local opts = {
                    redirect_uri_path = "/secure/redirect_uri",
                    discovery = "https://<openid-service-domain>/realms/<realm>/.well-known/openid-configuration",
                    client_id = "<client-id>",
                    -- Set the client to use JWS as an authentication method
                    token_endpoint_auth_method = "private_key_jwt",
                    client_rsa_private_key =[[
MIIEogIBAAKCAQEAiThmpvXBYdur716D2q7fYKirKxzZIU5QrkBGDvUOwg5izcTv
[...]
h2JHukolz9xf6qN61QMLSd83+kwoBr2drp6xg3eGDLIkQCQLrkY=
                    ]],
                    client_rsa_private_key_id = "265tDmmRsigvKPz8oygR0GcNdGX_naMP2cEGXR9Ueo0",
                   
                    
                    -- Encryption settings
                    --   client_rsa_private_enc_key is the RSA private key to be used to decrypt the JWE access_token / id_token generated by OP to authenticate the lua-resty-openidc RP.
                    --   client_rsa_private_enc_key_id is the key id to be set in the JWE header to identify which public key the OP has use to encrypt the access_token / id_token.
                    client_rsa_private_enc_key = [[
-----BEGIN PRIVATE KEY-----
MIIJKgIBAAKCAgEA1jhYqRlY7WiW36fzdFo4dxkwQXQhouhDlqJSu5MRiaPpwVLn
[...]
5zgUDtKKOXrDePay6pcaqjLKRc2nB8ljeNpYGsrQHAiK20EckOjHJZoH+1dy0Q==
-----END PRIVATE KEY-----
                    ]],
                    client_rsa_private_enc_key_id = "AAAtDmmRsigvKPz8oygR0GcNdGX_naMP2cEGXR9Ueo0",
                    -- end encryption settings
                    
                    
                    redirect_uri_scheme = "https",
                    session_contents = {id_token=true, user=true, enc_id_token=true, access_token=true},
                    token_signing_alg_values_expected = {"RS256"},
                    ssl_verify = "yes",
                    scope = "openid email profile",

                    logout_path = "/secure/logout",
                    redirect_after_logout_uri = "https://<openid-service-domain>/realms/<realm>/protocol/openid-connect/logout",
                    redirect_after_logout_with_id_token_hint = false,
                    post_logout_redirect_uri = "https://<website-domain>/"

                }
                local openidc = require("resty.openidc")
                local res, err = openidc.authenticate(opts)
                if err then
                    ngx.status = 403
                    ngx.say(err)
                    ngx.exit(ngx.HTTP_FORBIDDEN)
                end
                ngx.req.set_header('REMOTE_USER', res.id_token.email)
            }
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

## Support

For generic questions, see the Wiki pages with Frequently Asked Questions at:  
[https://github.com/zmartzone/lua-resty-openidc/wiki](https://github.com/zmartzone/lua-resty-openidc/wiki)  
Any questions/issues should go to the Github Discussons or Issues tracker.


## Disclaimer

*This software is open sourced by ZmartZone IAM but not supported commercially as such.
Any questions/issues should go to the Github Discussions or Issues tracker.
See also the DISCLAIMER file in this directory.*
