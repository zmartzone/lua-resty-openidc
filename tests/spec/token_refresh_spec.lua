local http = require("socket.http")
local test_support = require("test_support")
require 'busted.runner'()

describe("if there is an active non-expired login", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  local _, status = http.request({
    url = "http://localhost/default/t",
    redirect = false,
    headers = { cookie = cookies },
  })
  it("no redirect occurs on the next call", function()
    assert.are.equals(200, status)
  end)
  it("the access token is returned by authenticate", function()
    assert.is_not.error_log_contains("authenticate didn't return any access token")
  end)
end)

-- see https://github.com/zmartzone/lua-resty-openidc/issues/121
describe("if there is an active non-expired login and renew is disabled explicitly", function()
  test_support.start_server({
    oidc_opts = {
      renew_access_token_on_expiry = false
    }
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  local _, status = http.request({
    url = "http://localhost/default/t",
    redirect = false,
    headers = { cookie = cookies },
  })
  it("no redirect occurs on the next call", function()
    assert.are.equals(200, status)
  end)
  it("the access token is returned by authenticate", function()
    assert.is_not.error_log_contains("authenticate didn't return any access token")
  end)
end)

describe("if there is an active but expired login and refresh is not configured explicitly", function()
  test_support.start_server({
    token_response_expires_in = 0
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  os.execute("sleep 1.5")
  local _, status = http.request({
    url = "http://localhost/default/t",
    redirect = false,
    headers = { cookie = cookies },
  })
  it("no redirect occurs on the next call", function()
    assert.are.equals(200, status)
  end)
  it("the token gets refreshed", function()
    assert.error_log_contains("request body for token endpoint call: .*grant_type=refresh_token.*")
  end)
  -- token endpoint response contains id token by default
  it ("the id token gets refreshed", function()
    assert.error_log_contains("id_token refreshed")
  end)
  it("the access token is returned by authenticate", function()
    assert.is_not.error_log_contains("authenticate didn't return any access token")
  end)
end)

describe("if there is an active but expired login and refresh is enabled explicitly", function()
  test_support.start_server({
    token_response_expires_in = 0,
    oidc_opts = {
      renew_access_token_on_expiry = true
    }
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  os.execute("sleep 1.5")
  local _, status = http.request({
    url = "http://localhost/default/t",
    redirect = false,
    headers = { cookie = cookies },
  })
  it("no redirect occurs on the next call", function()
    assert.are.equals(200, status)
  end)
  it("the token gets refreshed", function()
    assert.error_log_contains("request body for token endpoint call: .*grant_type=refresh_token.*")
  end)
  it("the access token is returned by authenticate", function()
    assert.is_not.error_log_contains("authenticate didn't return any access token")
  end)
end)

describe("if there is an active but expired login and refresh is disabled explicitly", function()
  test_support.start_server({
    token_response_expires_in = 0,
    oidc_opts = {
      renew_access_token_on_expiry = false
    }
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  os.execute("sleep 1.5")
  local _, status = http.request({
    url = "http://localhost/default/t",
    redirect = false,
    headers = { cookie = cookies },
  })
  it("no redirect occurs on the next call", function()
    assert.are.equals(200, status)
  end)
  it("the token doesn't get refreshed", function()
    assert.is_not.error_log_contains("request body for token endpoint call: .*grant_type=refresh_token.*")
  end)
  it("no access token is returned by authenticate", function()
    assert.error_log_contains("authenticate didn't return any access token")
  end)
end)

describe("if there is an active but expired login and no refresh token", function()
  test_support.start_server({
    token_response_expires_in = 0,
    token_response_contains_refresh_token = "false"
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  os.execute("sleep 1.5")
  local _, status = http.request({
    url = "http://localhost/default/t",
    redirect = false,
    headers = { cookie = cookies },
  })
  it("a redirect occurs on the next call", function()
    assert.are.equals(302, status)
  end)
end)

-- https://github.com/zmartzone/lua-resty-openidc/issues/117
describe("if there is an active but expired login and refreshing it fails", function()
  test_support.start_server({
    token_response_expires_in = 0,
    refreshing_token_fails = "true",
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  os.execute("sleep 1.5")
  local _, status = http.request({
    url = "http://localhost/default/t",
    redirect = false,
    headers = { cookie = cookies },
  })
  it("a redirect occurs on the next call", function()
    assert.are.equals(302, status)
  end)
end)

describe("if token refresh doesn't add a new id_token", function()
  test_support.start_server({
    token_response_expires_in = 0,
    refresh_response_contains_id_token = "false",
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  os.execute("sleep 1.5")
  local _, status = http.request({
    url = "http://localhost/default/t",
    redirect = false,
    headers = { cookie = cookies },
  })
  it("no redirect occurs on the next call", function()
    assert.are.equals(200, status)
  end)
  it ("the id token doesn't get refreshed", function()
    assert.is_not.error_log_contains("id_token refreshed")
  end)
  it("the access token is returned by authenticate", function()
    assert.is_not.error_log_contains("authenticate didn't return any access token")
  end)
end)

describe("if refresh contains an invalid id_token", function()
  test_support.start_server({
    token_response_expires_in = 0,
    remove_refresh_id_token_claims = { "iss" }
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  os.execute("sleep 1.5")
  local _, status = http.request({
    url = "http://localhost/default/t",
    redirect = false,
    headers = { cookie = cookies },
  })
  it ("the id token doesn't get refreshed", function()
    assert.is_not.error_log_contains("id_token refreshed")
  end)
  it("the tokens are rejected", function()
    assert.error_log_contains("invalid id token, discarding tokens returned while refreshing")
  end)
  it("the access token is discarded", function()
    assert.error_log_contains("lost access token")
  end)
end)
