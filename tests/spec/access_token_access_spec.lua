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

describe("if there is an active non-expired login but access token is not stored in session", function()
  test_support.start_server({
    access_token_opts = {
      session_contents = {
        foo = true
      }
    },
    oidc_opts = {
      session_contents = {
        foo = true
      }
    }
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  local content_table = {}
  local _, status = http.request({
    url = "http://localhost/access_token",
    redirect = false,
    headers = { cookie = cookies },
    sink = ltn12.sink.table(content_table)
  })
  it("the access_token is not available", function()
    assert.are.equals(401, status)
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
    access_token_opts = {
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

describe("when discovery endpoint is not resolvable", function()
  test_support.start_server({
    access_token_opts = {
      discovery = "http://foo.example.org/"
    },
    token_response_expires_in = 0
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
  it("an error has been logged", function()
    assert.error_log_contains("access_token error: accessing discovery url.*foo.example.org could not be resolved.*")
  end)
end)

describe("when token endpoint is not resolvable", function()
  test_support.start_server({
    access_token_opts = {
      discovery = {
        token_endpoint = "http://foo.example.org/",
      }
    },
    token_response_expires_in = 0
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
  it("an error has been logged", function()
    assert.error_log_contains("access_token error: accessing token endpoint.*foo.example.org could not be resolved.*")
  end)
end)

describe("when token endpoint is not reachable", function()
  test_support.start_server({
    access_token_opts = {
      timeout = 40000,
      discovery = {
        token_endpoint = "http://192.0.2.1/"
      }
    },
    token_response_expires_in = 0
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
  it("an error has been logged", function()
    assert.error_log_contains("access_token error: accessing token endpoint.*%(http://192.0.2.1/%) failed")
  end)
end)

describe("when token endpoint is slow but no timeout is configured", function()
  test_support.start_server({
    delay_response = { token = 1000 },
    token_response_expires_in = 0
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  os.execute("sleep 1.5")
  local _, status = http.request({
    url = "http://localhost/access_token",
    redirect = false,
    headers = { cookie = cookies },
  })
  it("the access_token is available", function()
    assert.are.equals(200, status)
  end)
end)

describe("when token endpoint is slow and a simple timeout is configured", function()
  test_support.start_server({
    delay_response = { token = 1000 },
    access_token_opts = {
      timeout = 200
    },
    token_response_expires_in = 0
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
  it("an error has been logged", function()
    assert.error_log_contains("access_token error: accessing token endpoint.*%(http://127.0.0.1/token%) failed: timeout")
  end)
end)

describe("when token endpoint is slow and a table timeout is configured", function()
  test_support.start_server({
    delay_response = { token = 1000 },
    access_token_opts = {
      timeout = { read = 200 }
    },
    token_response_expires_in = 0
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
  it("an error has been logged", function()
    assert.error_log_contains("access_token error: accessing token endpoint.*%(http://127.0.0.1/token%) failed: timeout")
  end)
end)

describe("when token endpoint sends a 4xx status", function()
  test_support.start_server({
    access_token_opts = {
      discovery = {
        token_endpoint = "http://127.0.0.1/not-there"
      }
    },
    token_response_expires_in = 0
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
  it("an error has been logged", function()
    assert.error_log_contains("access_token error:.*response indicates failure, status=404,")
  end)
end)

describe("when token endpoint doesn't return proper JSON", function()
  test_support.start_server({
    access_token_opts = {
      discovery = {
        token_endpoint = "http://127.0.0.1/t"
      }
    },
    token_response_expires_in = 0
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
  it("an error has been logged", function()
    assert.error_log_contains("access_token error: JSON decoding failed")
  end)
end)
