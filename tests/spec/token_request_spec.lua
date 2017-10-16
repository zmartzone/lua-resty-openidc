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
  it("the request doesn't contain a basic auth header", function()
    assert.is_not.error_log_contains("token authorization header: Basic")
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
