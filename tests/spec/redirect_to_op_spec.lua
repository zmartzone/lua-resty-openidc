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

describe("when discovery endpoint is not resolvable", function()
  test_support.start_server({
    oidc_opts = {
      discovery = "http://foo.example.org/"
    },
  })
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("authenticate failed: accessing discovery url.*foo.example.org could not be resolved.*")
  end)
end)

describe("when discovery endpoint is not reachable", function()
  test_support.start_server({
    oidc_opts = {
      discovery = "http://192.0.2.1/"
    },
  })
  teardown(test_support.stop_server)
  local _, status = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("authenticate failed: accessing discovery url.*%(http://192.0.2.1/%) failed")
  end)
end)

describe("when discovery endpoint is slow and no timeout is configured", function()
  test_support.start_server({
    delay_response = { discovery = 1000 },
    oidc_opts = {
      discovery = "http://127.0.0.1/discovery"
    },
  })
  teardown(test_support.stop_server)
  local _, status = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("the response is a redirect", function()
    assert.are.equals(302, status)
  end)
end)

describe("when discovery endpoint is slow and a simple timeout is configured", function()
  test_support.start_server({
    delay_response = { discovery = 1000 },
    oidc_opts = {
      timeout = 200,
      discovery = "http://127.0.0.1/discovery"
    },
  })
  teardown(test_support.stop_server)
  local _, status = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("authenticate failed: accessing discovery url.*%(http://127.0.0.1/discovery%) failed: timeout")
  end)
end)

describe("when discovery endpoint is slow and a table timeout is configured", function()
  test_support.start_server({
    delay_response = { discovery = 1000 },
    oidc_opts = {
      timeout = { read = 200 },
      discovery = "http://127.0.0.1/discovery"
    },
  })
  teardown(test_support.stop_server)
  local _, status = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("authenticate failed: accessing discovery url.*%(http://127.0.0.1/discovery%) failed: timeout")
  end)
end)

describe("when discovery endpoint sends a 4xx status", function()
  test_support.start_server({
    oidc_opts = {
      discovery = "http://127.0.0.1/not-there"
    },
  })
  teardown(test_support.stop_server)
  local _, status = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("authenticate failed:.*response indicates failure, status=404,")
  end)
end)

describe("when discovery endpoint doesn't return proper JSON", function()
  test_support.start_server({
    oidc_opts = {
      discovery = "http://127.0.0.1/t"
    },
  })
  teardown(test_support.stop_server)
  local _, status = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("authenticate failed:.*JSON decoding failed")
  end)
end)

describe("when accessing the protected resource without token and x-forwarded headers exist", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    headers = {
      ["x-forwarded-proto"] = "https",
      ["x-forwarded-host"] = "example.org",
    },
    redirect = false
  })
  it("the configured forwarded information is used in redirect uri", function()
    assert.are.equals(302, status)
    local redir_escaped = test_support.urlescape_for_regex("https://example.org/default/redirect_uri")
    assert.truthy(string.match(string.lower(headers["location"]),
                               ".*redirect_uri=" .. string.lower(redir_escaped) .. ".*"))
  end)
end)

describe("when redir scheme is configured explicitly", function()
  test_support.start_server({
    oidc_opts = {
      redirect_uri_scheme = 'https',
    },
  })
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("it overrides the scheme actually used", function()
    assert.are.equals(302, status)
    local redir_escaped = test_support.urlescape_for_regex("https://127.0.0.1/default/redirect_uri")
    assert.truthy(string.match(string.lower(headers["location"]),
                               ".*redirect_uri=" .. string.lower(redir_escaped) .. ".*"))
  end)
end)

describe("when accessing the protected resource without token and x-forwarded-host contains a comma separated list", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    headers = {
      ["x-forwarded-proto"] = "https",
      ["x-forwarded-host"] = " example.org , example.com, foo.example.net"
    },
    redirect = false
  })
  it("the configured forwarded information is used in redirect uri", function()
    assert.are.equals(302, status)
    local redir_escaped = test_support.urlescape_for_regex("https://example.org/default/redirect_uri")
    assert.truthy(string.match(string.lower(headers["location"]),
                               ".*redirect_uri=" .. string.lower(redir_escaped) .. ".*"))
  end)
end)

describe("when accessing the protected resource without token and x-forwarded-* contain whitespace", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    headers = {
      ["x-forwarded-proto"] = " https ",
      ["x-forwarded-host"] = " example.org "
    },
    redirect = false
  })
  it("the values are trimmed", function()
    assert.are.equals(302, status)
    local redir_escaped = test_support.urlescape_for_regex("https://example.org/default/redirect_uri")
    assert.truthy(string.match(string.lower(headers["location"]),
                               ".*redirect_uri=" .. string.lower(redir_escaped) .. ".*"))
  end)
end)

describe("when accessing the protected resource without token and multiple x-forwarded-host headers", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  -- the http module doesn't support specifying multiple headers
  local r = io.popen("curl -H 'X-Forwarded-Host: example.org' -H 'X-Forwarded-Host: example.com'"
                       .. " -o /dev/null -v --max-redirs 0 http://127.0.0.1/default/t 2>&1")
  local o = r:read("*a")
  r:close()
  it("the first header is used", function()
    assert.truthy(string.match(string.lower(o), ".*http/.* 302"))
    local redir_escaped = test_support.urlescape_for_regex("http://example.org/default/redirect_uri")
    assert.truthy(string.match(string.lower(o),
                               ".*location: %S+redirect_uri=" .. string.lower(redir_escaped) .. ".*"))
  end)
end)

describe("when accessing the protected resource without token and a forwarded header exists", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    headers = {
      ["forwarded"] = "proto=https;Host=example.org",
    },
    redirect = false
  })
  it("the configured forwarded information is used in redirect uri", function()
    assert.are.equals(302, status)
    local redir_escaped = test_support.urlescape_for_regex("https://example.org/default/redirect_uri")
    assert.truthy(string.match(string.lower(headers["location"]),
                               ".*redirect_uri=" .. string.lower(redir_escaped) .. ".*"))
  end)
end)

describe("when accessing the protected resource without token and a forwarded header values are quoted", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    headers = {
      ["forwarded"] = 'proTo="https";Host="example.org"',
    },
    redirect = false
  })
  it("the configured forwarded information is used unquoted in redirect uri", function()
    assert.are.equals(302, status)
    local redir_escaped = test_support.urlescape_for_regex("https://example.org/default/redirect_uri")
    assert.truthy(string.match(string.lower(headers["location"]),
                               ".*redirect_uri=" .. string.lower(redir_escaped) .. ".*"))
  end)
end)

describe("when accessing the protected resource without token and a forwarded header has multiple fields", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    headers = {
      ["forwarded"] = 'proTo="https";Host="example.org",host=example.com',
    },
    redirect = false
  })
  it("the configured forwarded information is used unquoted in redirect uri", function()
    assert.are.equals(302, status)
    local redir_escaped = test_support.urlescape_for_regex("https://example.org/default/redirect_uri")
    assert.truthy(string.match(string.lower(headers["location"]),
                               ".*redirect_uri=" .. string.lower(redir_escaped) .. ".*"))
  end)
end)

describe("when accessing the protected resource without token and multiple forwarded headers", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  -- the http module doesn't support specifying multiple headers
  local r = io.popen("curl -H 'Forwarded: host=example.org' -H 'Forwarded: host=example.com'"
                       .. " -o /dev/null -v --max-redirs 0 http://127.0.0.1/default/t 2>&1")
  local o = r:read("*a")
  r:close()
  it("the first header is used", function()
    assert.truthy(string.match(string.lower(o), ".*http/.* 302"))
    local redir_escaped = test_support.urlescape_for_regex("http://example.org/default/redirect_uri")
    assert.truthy(string.match(string.lower(o),
                               ".*location: %S+redirect_uri=" .. string.lower(redir_escaped) .. ".*"))
  end)
end)

