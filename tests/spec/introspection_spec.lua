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
    it("no cookies are sent with the introspection request", function()
      assert.error_log_contains("no cookie in introspection call")
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

describe("when cookies shall be sent with the introspection call", function()
  test_support.start_server({
    introspection_opts = {
      pass_cookies = "foo bar"
    }
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  describe("but no cookies are included in request", function()
    local _, status = http.request({
      url = "http://127.0.0.1/introspect",
      headers = {
        authorization = "Bearer " .. jwt,
      }
    })
    it("the response is valid", function()
      assert.are.equals(200, status)
    end)
    it("the request doesn't contain any cookies", function()
      assert.error_log_contains("no cookie in introspection call")
    end)
  end)
  describe("a cookie is included in request", function()
    local _, status = http.request({
      url = "http://127.0.0.1/introspect",
      headers = {
        authorization = "Bearer " .. jwt,
        cookie = "foo=x; baz=y"
      }
    })
    it("the response is valid", function()
      assert.are.equals(200, status)
    end)
    it("the request contains the cookie", function()
      assert.error_log_contains("cookie foo=x in introspection call")
    end)
  end)
  describe("multiple cookie headers are included in request", function()
    -- the http module doesn't support specifying multiple headers
             local r = io.popen("curl -H 'Authorization: Bearer " .. jwt .. "' -H 'Cookie: foo=x'"
                         .. " -H 'Cookie: baz=y'"
                         .. " -o /dev/null -v --max-redirs 0 http://127.0.0.1/introspect 2>&1")
    local o = r:read("*a")
    r:close()
    it("the response is valid", function()
      assert.truthy(string.match(string.lower(o), ".*http/.* 200"))
    end)
    it("the request contains the cookie", function()
      assert.error_log_contains("cookie foo=x in introspection call")
    end)
  end)
end)

describe("when auth_accept_token_as is header and default header name is used", function()
  test_support.start_server({
    introspection_opts = {
      auth_accept_token_as = "header"
    }
  })
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
    it("no cookies are sent with the introspection request", function()
      assert.error_log_contains("no cookie in introspection call")
    end)
    it("the response is valid", function()
      assert.are.equals(200, status)
    end)
  end)
end)

describe("when auth_accept_token_as is header and auth_accept_token_as_header_name is defined", function()
  test_support.start_server({
    introspection_opts = {
      auth_accept_token_as = "header",
      auth_accept_token_as_header_name="cf-Access-Jwt-Assertion"
    }
  })
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
  describe("with a bearer token pattern1", function()
    local _, status = http.request({
      url = "http://127.0.0.1/introspect",
      headers = { ["cf-Access-Jwt-Assertion"] = "Bearer " .. jwt }
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
    it("no cookies are sent with the introspection request", function()
      assert.error_log_contains("no cookie in introspection call")
    end)
    it("the response is valid", function()
      assert.are.equals(200, status)
    end)
  end)
end)

describe("when auth_accept_token_as is cookie and default cookie name is used", function()
  test_support.start_server({
    introspection_opts = {
      auth_accept_token_as = "cookie"
    }
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  describe("without any cookie", function()
    local _, status = http.request({
      url = "http://127.0.0.1/introspect"
    })
    it("the token is invalid", function()
      assert.are.equals(401, status)
    end)
    it("an error is logged", function()
      assert.error_log_contains("no Cookie header found")
    end)
  end)
  describe("without default cookie", function()
    local _, status = http.request({
      url = "http://127.0.0.1/introspect",
      headers = { cookie = "token=" .. jwt }
    })
    it("the token is invalid", function()
      assert.are.equals(401, status)
    end)
    it("an error is logged", function()
      assert.error_log_contains("no Cookie PA.global found")
    end)
  end)
  describe("with proper cookie", function()
    local _, status = http.request({
      url = "http://127.0.0.1/introspect",
      headers = { cookie = "PA.global=" .. jwt }
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
    it("no cookies are sent with the introspection request", function()
      assert.error_log_contains("no cookie in introspection call")
    end)
    it("the response is valid", function()
      assert.are.equals(200, status)
    end)
  end)
end)

describe("when auth_accept_token_as is cookie:foo", function()
  test_support.start_server({
    introspection_opts = {
      auth_accept_token_as = "cookie:foo"
    }
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  describe("without any cookie", function()
    local _, status = http.request({
      url = "http://127.0.0.1/introspect"
    })
    it("the token is invalid", function()
      assert.are.equals(401, status)
    end)
    it("an error is logged", function()
      assert.error_log_contains("no Cookie header found")
    end)
  end)
  describe("without foo cookie", function()
    local _, status = http.request({
      url = "http://127.0.0.1/introspect",
      headers = { cookie = "token=" .. jwt }
    })
    it("the token is invalid", function()
      assert.are.equals(401, status)
    end)
    it("an error is logged", function()
      assert.error_log_contains("no Cookie foo found")
    end)
  end)
  describe("with proper cookie", function()
    local _, status = http.request({
      url = "http://127.0.0.1/introspect",
      headers = { cookie = "foo=" .. jwt }
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
    it("no cookies are sent with the introspection request", function()
      assert.error_log_contains("no cookie in introspection call")
    end)
    it("the response is valid", function()
      assert.are.equals(200, status)
    end)
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

describe("when introspection endpoint is slow but no timeout is configured", function()
  test_support.start_server({
    delay_response = { introspection = 1000 },
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

describe("when introspection endpoint is slow and a simple timeout is configured", function()
  test_support.start_server({
    delay_response = { introspection = 1000 },
    introspection_opts = {
      timeout = 200,
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
    assert.error_log_contains("Introspection error:.*accessing introspection endpoint %(http://127.0.0.1/introspection%) failed: timeout")
  end)
end)

describe("when introspection endpoint is slow and a table timeout is configured", function()
  test_support.start_server({
    delay_response = { introspection = 1000 },
    introspection_opts = {
      timeout = { read = 200 },
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
    assert.error_log_contains("Introspection error:.*accessing introspection endpoint %(http://127.0.0.1/introspection%) failed: timeout")
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
