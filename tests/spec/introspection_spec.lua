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

describe("when the response is active but lacks the exp claim", function()
  test_support.start_server({
    remove_introspection_claims = { "exp" }
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
end)

-- TODO find a way to assert caching

describe("when introspection endpoint is not resolvable", function()
  test_support.start_server({
    introspection_opts = {
      introspection_endpoint = "http://foo.example.org/"
    },
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
    assert.error_log_contains("Introspection error:.*foo.example.org could not be resolved.*")
  end)
end)

describe("when introspection endpoint is not reachable", function()
  test_support.start_server({
    introspection_opts = {
      introspection_endpoint = "http://192.0.2.1/"
    },
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
    assert.error_log_contains("Introspection error:.*accessing introspection endpoint %(http://192.0.2.1/%) failed")
  end)
end)

describe("when introspection endpoint sends a 4xx status", function()
  test_support.start_server({
    introspection_opts = {
      introspection_endpoint = "http://127.0.0.1/not-there"
    },
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
    assert.error_log_contains("Introspection error:.*response indicates failure, status=404,")
  end)
end)

describe("when introspection endpoint doesn't return proper JSON", function()
  test_support.start_server({
    introspection_opts = {
      introspection_endpoint = "http://127.0.0.1/t"
    },
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
    assert.error_log_contains("Introspection error: JSON decoding failed")
  end)
end)
