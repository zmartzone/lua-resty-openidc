local http = require("socket.http")
local test_support = require("test_support")
require 'busted.runner'()

local function assert_introspection_endpoint_call_contains(s, case_insensitive)
   assert.error_log_contains("Received introspection request: .*" ..  s .. ".*",
                             case_insensitive)
end

describe("when the introspection endpoint is invoked", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  describe("without any Authorization header", function()
    local _, status = http.request({
      url = "http://127.0.0.1/introspect"
    })
    it("the token is invalid", function()
      assert.are.equals(401, status)
    end)
    it("an error is logged", function()
      assert.error_log_contains("no Authorization header found")
    end)
  end)
  describe("with a bearer token", function()
    local _, status = http.request({
      url = "http://127.0.0.1/introspect",
      headers = { authorization = "Bearer " .. jwt }
    })
    it("the request contains the client_id parameter", function()
      assert_introspection_endpoint_call_contains("client_id=client_id")
    end)
    it("the request contains the client_secret parameter", function()
      assert_introspection_endpoint_call_contains("client_secret=client_secret")
    end)
    it("the request contains the token parameter", function()
      assert_introspection_endpoint_call_contains("token=" .. jwt:gsub("%-", "%%%-"))
    end)
    it("the response is valid", function()
      assert.are.equals(200, status)
    end)
  end)
end)

describe("when a different token parameter name is configured", function()
  test_support.start_server({
    introspection_opts = {
      introspection_token_param_name = "foo"
    }
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/introspect",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the response is valid", function()
    assert.are.equals(200, status)
  end)
  it("the request contains the renamed token parameter", function()
    assert_introspection_endpoint_call_contains("foo=" .. jwt:gsub("%-", "%%%-"))
  end)
end)

describe("when additional parameters have been configured", function()
  test_support.start_server({
    introspection_opts = {
      introspection_params = {
        x = "y",
        z = "a"
      }
    }
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/introspect",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the response is valid", function()
    assert.are.equals(200, status)
  end)
  it("the request contains the parameters", function()
    assert_introspection_endpoint_call_contains("x=y")
    assert_introspection_endpoint_call_contains("z=a")
  end)
end)

describe("when the response is inactive", function()
  test_support.start_server({
    introspection_response = {
      active = false
    },
    -- TODO shouldn't be neccesary, see https://github.com/pingidentity/lua-resty-openidc/commit/1e2d705708531a5e584a612391243cf6bf324840#commitcomment-25265312
    remove_introspection_claims = { "exp" }
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/introspect",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("Introspection error: invalid token")
  end)
end)

-- TODO find a way to assert caching
