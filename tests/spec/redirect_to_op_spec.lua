local http = require("socket.http")
local test_support = require("test_support")
require 'busted.runner'()

describe("when accessing the protected resource without token", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("redirects to the authorization endpoint", function()
    assert.are.equals(302, status)
    assert.truthy(string.match(headers["location"], "http://127.0.0.1/authorize%?.*client_id=client_id.*"))
  end)
  it("requests the authorization code grant flow", function()
    assert.truthy(string.match(headers["location"], ".*response_type=code.*"))
  end)
  it("uses the configured redirect uri", function()
    local redir_escaped = test_support.urlescape_for_regex("http://127.0.0.1/default/redirect_uri")
    -- lower as url.escape uses %2f for a slash, openidc uses %2F
    assert.truthy(string.match(string.lower(headers["location"]),
                               ".*redirect_uri=" .. string.lower(redir_escaped) .. ".*"))
  end)
  it("uses a state parameter", function()
    assert.truthy(string.match(headers["location"], ".*state=.*"))
  end)
  it("uses a nonce parameter", function()
    assert.truthy(string.match(headers["location"], ".*nonce=.*"))
  end)
  it("uses the default scopes", function()
    assert.truthy(string.match(headers["location"],
                               ".*scope=" .. test_support.urlescape_for_regex("openid email profile") .. ".*"))
  end)
  it("doesn't use the prompt parameter", function()
    assert.falsy(string.match(headers["location"], ".*prompt=.*"))
  end)
end)

describe("when accessing the custom protected resource without token", function()
  test_support.start_server({oidc_opts = {scope = "my-scope"}})
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("uses the configured scope", function()
    assert.truthy(string.match(headers["location"], ".*scope=my%-scope.*"))
  end)
end)

describe("when explicitly asking for a prompt parameter", function()
  test_support.start_server({oidc_opts = {prompt = "none"}})
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("then it is included", function()
    assert.truthy(string.match(headers["location"], ".*prompt=none.*"))
  end)
end)

describe("when explicitly asking for a display parameter", function()
  test_support.start_server({oidc_opts = {display = "page"}})
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("then it is included", function()
    assert.truthy(string.match(headers["location"], ".*display=page.*"))
  end)
end)

describe("when explicitly asking for custom parameters", function()
  test_support.start_server({
      oidc_opts = {
        ["authorization_params"] = {
          test = "abc",
          foo = "bar",
        }
      }
  })
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("then they are included", function()
    assert.truthy(string.match(headers["location"], ".*test=abc.*"))
    assert.truthy(string.match(headers["location"], ".*foo=bar.*"))
  end)
end)

describe("when discovery data must be loaded", function()
  test_support.start_server({
      oidc_opts = {
        discovery = "http://127.0.0.1/discovery"
      }
  })
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("the authorization request redirects to the discovered authorization endpoint", function()
    assert.are.equals(302, status)
    assert.truthy(string.match(headers["location"], "http://127.0.0.1/authorize%?.*client_id=client_id.*"))
  end)
end)
