local test_support = require("test_support")
require 'busted.runner'()

local function assert_token_endpoint_call_contains(s, case_insensitive)
   assert.error_log_contains("request body for token endpoint call: .*" ..  s .. ".*",
                             case_insensitive)
end

describe("when the token endpoint is invoked", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local state = test_support.login()
  it("the request contains the authorization_code grant type", function()
    assert_token_endpoint_call_contains("grant_type=authorization_code")
  end)
  it("the request contains the authorization code", function()
    assert_token_endpoint_call_contains("code=foo")
  end)
  it("the request contains the state parameter", function()
    assert_token_endpoint_call_contains("state=" .. state)
  end)
  it("the request contains the redirect uri", function()
    local redir_escaped = test_support.urlescape_for_regex("http://localhost/default/redirect_uri")
    assert_token_endpoint_call_contains("redirect_uri=" .. redir_escaped, true)
  end)
  it("the request contains the client_id parameter", function()
    assert_token_endpoint_call_contains("client_id=client_id")
  end)
  -- only auth_method in default discovery is client_secret_post
  it("the request contains the client_secret parameter", function()
    assert_token_endpoint_call_contains("client_secret=client_secret")
  end)
  it("the request doesn't contain any basic auth header", function()
    assert.is_not.error_log_contains("token authorization header: Basic")
  end)
  it("the request doesn't contain any client_assertion_type parameter", function()
    assert.is_not.error_log_contains("request body for token endpoint call: .*client_assertion_type=")
  end)
  it("the request doesn't contain any client_assertion parameter", function()
    assert.is_not.error_log_contains("request body for token endpoint call: .*client_assertion=.*")
  end)
end)

describe("when the token endpoint is invoked using client_secret_basic", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        token_endpoint_auth_methods_supported = { "client_secret_basic" },
      }
    }
  })
  teardown(test_support.stop_server)
  test_support.login()
  it("the request doesn't contain the client_secret as parameter", function()
    assert.is_not.error_log_contains("request body for token endpoint call: .*client_secret=client_secret.*")
  end)
  it("the request contains a basic auth header", function()
    assert.error_log_contains("token authorization header: Basic")
  end)
  it("the request doesn't contain any client_assertion_type parameter", function()
    assert.is_not.error_log_contains("request body for token endpoint call: .*client_assertion_type=")
  end)
  it("the request doesn't contain any client_assertion parameter", function()
    assert.is_not.error_log_contains("request body for token endpoint call: .*client_assertion=.*")
  end)
end)

describe("when no explicit auth method is configured #96", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        token_endpoint_auth_methods_supported = { "foo", "client_secret_basic", "client_secret_post" },
      }
    }
  })
  teardown(test_support.stop_server)
  test_support.login()
  it("the first method supported is used", function()
    assert.error_log_contains("token authorization header: Basic")
  end)
end)

describe("when an explicit auth method is configured", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        token_endpoint_auth_methods_supported = { "foo", "client_secret_basic", "client_secret_post" },
      },
      token_endpoint_auth_method = "client_secret_post"
    }
  })
  teardown(test_support.stop_server)
  test_support.login()
  it("then it is used", function()
    assert_token_endpoint_call_contains("client_secret=client_secret")
  end)
end)

describe("when 'private_key_jwt' auth method is configured", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        token_endpoint_auth_methods_supported = { "client_secret_basic", "client_secret_post", "private_key_jwt" },
      },
      token_endpoint_auth_method = "private_key_jwt",
      client_rsa_private_key = test_support.load("/spec/private_rsa_key.pem")
    }
  })
  teardown(test_support.stop_server)
  test_support.login()
  it("then it is used", function()
    assert_token_endpoint_call_contains("client_assertion=ey")  -- check only beginning of the assertion as it changes each time
    assert_token_endpoint_call_contains("client_assertion_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Aclient%-assertion%-type%%3Ajwt%-bearer")
  end)
end)

describe("when 'private_key_jwt' auth method is configured but no key specified", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        token_endpoint_auth_methods_supported = { "client_secret_basic", "client_secret_post", "private_key_jwt" },
      },
      token_endpoint_auth_method = "private_key_jwt",
    }
  })
  teardown(test_support.stop_server)
  test_support.login()
  it("then it is not used", function()
    assert.error_log_contains("token authorization header: Basic")
  end)
end)

describe("if token endpoint is not resolvable", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        token_endpoint = "http://foo.example.org/"
      }
    },
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login fails", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("authenticate failed:.*foo.example.org could not be resolved.*")
  end)
end)

describe("if token endpoint is not reachable", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        token_endpoint = "http://192.0.2.1/"
      }
    },
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login fails", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("authenticate failed:.*accessing token endpoint %(http://192.0.2.1/%) failed")
  end)
end)

describe("if token endpoint is slow and no timeout is configured", function()
  test_support.start_server({
    delay_response = { token = 1000 },
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login succeeds", function()
    assert.are.equals(302, status)
  end)
end)

describe("if token endpoint is slow and a simple timeout is configured", function()
  test_support.start_server({
    delay_response = { token = 1000 },
    oidc_opts = {
      timeout = 200,
    },
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login fails", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("authenticate failed:.*accessing token endpoint %(http://127.0.0.1/token%) failed: timeout")
  end)
end)

describe("if token endpoint is slow and a table timeout is configured", function()
  test_support.start_server({
    delay_response = { token = 1000 },
    oidc_opts = {
      timeout = { read = 200 },
    },
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login fails", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("authenticate failed:.*accessing token endpoint %(http://127.0.0.1/token%) failed: timeout")
  end)
end)

describe("if token endpoint sends a 4xx status", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        token_endpoint = "http://127.0.0.1/not-there"
      }
    },
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login fails", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("authenticate failed:.*response indicates failure, status=404,")
  end)
end)

describe("if token endpoint doesn't return proper JSON", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        token_endpoint = "http://127.0.0.1/t"
      }
    },
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login fails", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("authenticate failed: JSON decoding failed")
  end)
end)

describe("when a request_decorator has been specified when calling the token endpoint", function()
  test_support.start_server({
    oidc_opts = {
      decorate = "body"
    }
  })
  teardown(test_support.stop_server)
  test_support.login()
  it("the request contains the additional parameter", function()
    assert_token_endpoint_call_contains("foo=bar")
  end)
end)

local function extract_jwt_from_error_log()
  local log = test_support.load("/tmp/server/logs/error.log")
  local encoded_jwt = log:match("request body for token endpoint call: .*client_assertion=([^\n&]+)")
  local enc_hdr, enc_payload, enc_sign = string.match(encoded_jwt, '^(.+)%.(.+)%.(.*)$')
  local base64_url_decode = function(s)
    local mime = require "mime"
    return mime.unb64(s:gsub('-','+'):gsub('_','/'))
  end
  local dkjson = require "dkjson"
  return {
      header = dkjson.decode(base64_url_decode(enc_hdr), 1, nil),
      payload = dkjson.decode(base64_url_decode(enc_payload), 1, nil),
      signature = enc_sign
  }
end

describe("when the token endpoint is invoked using client_secret_jwt", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        token_endpoint_auth_methods_supported = { "client_secret_jwt" },
      }
    }
  })
  teardown(test_support.stop_server)
  test_support.login()
  it("the request doesn't contain the client_secret as parameter", function()
    assert.is_not.error_log_contains("request body for token endpoint call: .*client_secret=client_secret.*")
  end)
  it("the request doesn't contain a basic auth header", function()
    assert.is_not.error_log_contains("token authorization header: Basic")
  end)
  it("the request contains the proper client_assertion_type parameter", function()
    -- url.escape escapes the "-" while openidc doesn't so we must revert the encoding for comparison
    local at = test_support.urlescape_for_regex("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
      :gsub("%%%%2d", "%%-")
    assert.error_log_contains("request body for token endpoint call: .*client_assertion_type="..at..".*", true)
  end)
  it("the request contains a client_assertion parameter", function()
    assert.error_log_contains("request body for token endpoint call: .*client_assertion=.*")
  end)
  describe("then the submitted JWT", function()
    local jwt = extract_jwt_from_error_log()
    it("has a proper HMAC header", function()
      assert.are.equal("JWT", jwt.header.typ)
      assert.are.equal("HS256", jwt.header.alg)
    end)
    it("is signed", function()
      assert.truthy(jwt.signature)
    end)
    it("contains the client_id as iss claim", function()
      assert.are.equal("client_id", jwt.payload.iss)
    end)
    it("contains the client_id as sub claim", function()
      assert.are.equal("client_id", jwt.payload.sub)
    end)
    it("contains the token endpoint as aud claim", function()
      assert.are.equal("http://127.0.0.1/token", jwt.payload.aud)
    end)
    it("contains a jti claim", function()
      assert.truthy(jwt.payload.jti)
    end)
    it("contains a non-expired exp claim", function()
      assert.truthy(jwt.payload.exp)
      assert.is_true(jwt.payload.exp > os.time())
    end)
  end)
end)

describe("when 'client_secret_jwt' auth method is configured but no key specified", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        token_endpoint_auth_methods_supported = { "client_secret_basic", "client_secret_post", "client_secret_jwt" },
      },
      token_endpoint_auth_method = "client_secret_jwt",
    },
    remove_oidc_config_keys = { "client_secret" }
  })
  teardown(test_support.stop_server)
  test_support.login()
  it("then it is not used", function()
    assert.error_log_contains("token authorization header: Basic")
  end)
end)

