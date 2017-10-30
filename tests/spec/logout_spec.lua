local http = require("socket.http")
local test_support = require("test_support")
require 'busted.runner'()

describe("when the configured logout uri is invoked with a non-image request", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = "http://127.0.0.1/default/logout",
      headers = { cookie = cookie },
      redirect = false
  })
  it("the response contains a default HTML-page", function()
    assert.are.equals(200, status)
    assert.are.equals("text/html", headers["content-type"])
    -- TODO should there be a Cache-Control header
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
                               "session=; Expires=Thu, 01 Jan 1970 00:00:01 GMT.*"))
  end)
end)

describe("when the configured logout uri is invoked with a png request", function()
  -- TODO should this really take precedence over a configured end_session_endpoint?
  test_support.start_server({
      oidc_opts = {
        discovery = {
          end_session_endpoint = "http://127.0.0.1/end-session"
        }
      }
  })
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = "http://127.0.0.1/default/logout",
      headers = { cookie = cookie, accept = "image/png" },
      redirect = false
  })
  it("the response contains a default HTML-page", function()
    assert.are.equals(200, status)
    assert.are.equals("image/png", headers["content-type"])
    assert.are.equals("no-cache, no-store", headers["cache-control"])
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
                               "session=; Expires=Thu, 01 Jan 1970 00:00:01 GMT.*"))
  end)
end)

describe("when logout is invoked and a callback with hint has been configured", function()
  test_support.start_server({
      oidc_opts = {
        discovery = {
          end_session_endpoint = "http://127.0.0.1/end-session",
          ping_end_session_endpoint = "http://127.0.0.1/ping-end-session",
        },
        redirect_after_logout_uri = "http://127.0.0.1/after-logout",
        redirect_after_logout_with_id_token_hint = true,
      }
  })
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = "http://127.0.0.1/default/logout",
      headers = { cookie = cookie },
      redirect = false
  })
  it("the response redirects to the callback", function()
    assert.are.equals(302, status)
    assert.truthy(string.match(headers["location"], "http://127.0.0.1/after%-logout.*"))
  end)
  it("the redirect contains the id_token_hint", function()
    assert.truthy(string.match(headers["location"], ".*%?id_token_hint=.*"))
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
                               "session=; Expires=Thu, 01 Jan 1970 00:00:01 GMT.*"))
  end)
end)

describe("when logout is invoked and a callback with hint has been configured - callback contains question mark", function()
  test_support.start_server({
      oidc_opts = {
        discovery = {
          end_session_endpoint = "http://127.0.0.1/end-session",
          ping_end_session_endpoint = "http://127.0.0.1/ping-end-session",
        },
        redirect_after_logout_uri = "http://127.0.0.1/after-logout?foo=bar",
        redirect_after_logout_with_id_token_hint = true,
      }
  })
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = "http://127.0.0.1/default/logout",
      headers = { cookie = cookie },
      redirect = false
  })
  it("the response redirects to the callback", function()
    assert.are.equals(302, status)
    assert.truthy(string.match(headers["location"], "http://127.0.0.1/after%-logout%?foo=bar.*"))
  end)
  it("the redirect contains the id_token_hint", function()
    assert.truthy(string.match(headers["location"], ".*%&id_token_hint=.*"))
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
                               "session=; Expires=Thu, 01 Jan 1970 00:00:01 GMT.*"))
  end)
end)

describe("when logout is invoked and a callback with hint has been configured but id_token hasn't been cached", function()
  test_support.start_server({
      oidc_opts = {
        discovery = {
          end_session_endpoint = "http://127.0.0.1/end-session",
          ping_end_session_endpoint = "http://127.0.0.1/ping-end-session",
        },
        redirect_after_logout_uri = "http://127.0.0.1/after-logout",
        redirect_after_logout_with_id_token_hint = true,
        session_contents = {
          access_token = true
        }
      }
  })
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = "http://127.0.0.1/default/logout",
      headers = { cookie = cookie },
      redirect = false
  })
  it("the response redirects to the callback", function()
    assert.are.equals(302, status)
    assert.truthy(string.match(headers["location"], "http://127.0.0.1/after%-logout.*"))
  end)
  it("the redirect doesn't contain the id_token_hint", function()
    assert.falsy(string.match(headers["location"], ".*id_token_hint=.*"))
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
                               "session=; Expires=Thu, 01 Jan 1970 00:00:01 GMT.*"))
  end)
end)

describe("when logout is invoked and a callback without hint has been configured", function()
  test_support.start_server({
      oidc_opts = {
        discovery = {
          end_session_endpoint = "http://127.0.0.1/end-session",
          ping_end_session_endpoint = "http://127.0.0.1/ping-end-session",
        },
        redirect_after_logout_uri = "http://127.0.0.1/after-logout",
      }
  })
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = "http://127.0.0.1/default/logout",
      headers = { cookie = cookie },
      redirect = false
  })
  it("the response redirects to the callback", function()
    assert.are.equals(302, status)
    assert.truthy(string.match(headers["location"], "http://127.0.0.1/after%-logout.*"))
  end)
  it("the redirect doesn't contain the id_token_hint", function()
    assert.falsy(string.match(headers["location"], ".*id_token_hint=.*"))
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
                               "session=; Expires=Thu, 01 Jan 1970 00:00:01 GMT.*"))
  end)
end)

describe("when logout is invoked and discovery contains end_session_endpoint and the id_token has been cached", function()
  test_support.start_server({
      oidc_opts = {
        discovery = {
          end_session_endpoint = "http://127.0.0.1/end-session",
          ping_end_session_endpoint = "http://127.0.0.1/ping-end-session",
        },
      }
  })
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = "http://127.0.0.1/default/logout",
      headers = { cookie = cookie },
      redirect = false
  })
  it("the response redirects to the callback", function()
    assert.are.equals(302, status)
    assert.truthy(string.match(headers["location"], "http://127.0.0.1/end%-session.*"))
  end)
  it("the redirect contains the id_token_hint", function()
    assert.truthy(string.match(headers["location"], ".*%id_token_hint=.*"))
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
                               "session=; Expires=Thu, 01 Jan 1970 00:00:01 GMT.*"))
  end)
end)

describe("when logout is invoked and discovery contains end_session_endpoint and the id_token hasn't been cached", function()
  test_support.start_server({
      oidc_opts = {
        discovery = {
          end_session_endpoint = "http://127.0.0.1/end-session",
          ping_end_session_endpoint = "http://127.0.0.1/ping-end-session",
        },
        session_contents = {
          access_token = true
        }
      }
  })
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = "http://127.0.0.1/default/logout",
      headers = { cookie = cookie },
      redirect = false
  })
  it("the response redirects to the callback", function()
    assert.are.equals(302, status)
    assert.truthy(string.match(headers["location"], "http://127.0.0.1/end%-session.*"))
  end)
  it("the redirect contains the id_token_hint", function()
    assert.falsy(string.match(headers["location"], ".*%id_token_hint=.*"))
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
                               "session=; Expires=Thu, 01 Jan 1970 00:00:01 GMT.*"))
  end)
end)

describe("when logout is invoked and discovery contains ping_end_session_endpoint", function()
  test_support.start_server({
      oidc_opts = {
        discovery = {
          ping_end_session_endpoint = "http://127.0.0.1/ping-end-session",
        },
      }
  })
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = "http://127.0.0.1/default/logout",
      headers = { cookie = cookie },
      redirect = false
  })
  it("the response redirects to the callback", function()
    assert.are.equals(302, status)
    assert.truthy(string.match(headers["location"], "http://127.0.0.1/ping%-end%-session.*"))
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
                               "session=; Expires=Thu, 01 Jan 1970 00:00:01 GMT.*"))
  end)
end)
