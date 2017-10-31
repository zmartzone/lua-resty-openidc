local http = require("socket.http")
local test_support = require("test_support")
local ltn12 = require("ltn12")
require 'busted.runner'()

local function assert_token_endpoint_call_contains(s, case_insensitive)
   assert.error_log_contains("request body for token endpoint call: .*" ..  s .. ".*",
                             case_insensitive)
end

describe("if there is no active user session", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, status = http.request({
    url = "http://localhost/access_token",
    redirect = false,
  })
  it("the access_token is not available", function()
    assert.are.equals(401, status)
  end)
end)

describe("if there is an active non-expired login", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  local content_table = {}
  local _, status = http.request({
    url = "http://localhost/access_token",
    redirect = false,
    headers = { cookie = cookies },
    sink = ltn12.sink.table(content_table)
  })
  it("the access_token is available", function()
    assert.are.equals(200, status)
  end)
  it("the access_token is returned", function()
    assert.are.equals("a_token\n", table.concat(content_table))
  end)
end)

describe("if there is an active but expired login", function()
  test_support.start_server({
    token_response_expires_in = 0
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  os.execute("sleep 1.5")
  local content_table = {}
  local _, status = http.request({
    url = "http://localhost/access_token",
    redirect = false,
    headers = { cookie = cookies },
    sink = ltn12.sink.table(content_table)
  })
  it("the access_token is available", function()
    assert.are.equals(200, status)
  end)
  it("the token_request uses the refresh_token grant", function()
    assert_token_endpoint_call_contains("grant_type=refresh_token")
  end)
  it("the request contains the client_id parameter", function()
    assert_token_endpoint_call_contains("client_id=client_id")
  end)
  it("the request contains the client_secret parameter", function()
    assert_token_endpoint_call_contains("client_secret=client_secret")
  end)
  it("the request contains the refresh_token", function()
    assert_token_endpoint_call_contains("refresh_token=r_token")
  end)
  it("the request contains the default scopes", function()
    assert_token_endpoint_call_contains("scope=openid%%20email%%20profile")
  end)
  it("the refreshed access_token is returned", function()
    assert.are.equals("a_token2\n", table.concat(content_table))
  end)
end)

describe("if the login asked for custom scopes", function()
  test_support.start_server({
    oidc_opts = {
      scope = "my-scope"
    },
    token_response_expires_in = 0
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  os.execute("sleep 1.5")
  local content_table = {}
  local _, status = http.request({
    url = "http://localhost/access_token",
    redirect = false,
    headers = { cookie = cookies },
    sink = ltn12.sink.table(content_table)
  })
  it("the request doesn't contain the default scopes", function()
    assert.is_not.error_log_contains("request body for token endpoint call: .*scope=openid%%20email%%20profile.*")
  end)
  it("the request contains the custom scope", function()
    assert_token_endpoint_call_contains("scope=my%-scope")
  end)
  it("the refreshed access_token is returned", function()
    assert.are.equals("a_token2\n", table.concat(content_table))
  end)
end)

describe("if no refresh_token has been provided and login has expired", function()
  test_support.start_server({
    token_response_expires_in = 0,
    token_response_contains_refresh_token = "false"
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  os.execute("sleep 1.5")
  local _, status = http.request({
    url = "http://localhost/access_token",
    redirect = false,
    headers = { cookie = cookies },
  })
  it("the access_token is not available", function()
    assert.are.equals(401, status)
  end)
end)

