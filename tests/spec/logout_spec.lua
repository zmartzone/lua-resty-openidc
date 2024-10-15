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
    -- TODO should there be a Cache-Control header?
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
  end)
end)

describe("when the configured logout uri is invoked with Firefox 128's default Accept", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = "http://127.0.0.1/default/logout",
      headers = { cookie = cookie, accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8" },
      redirect = false
  })
  it("the response contains a default HTML-page", function()
    assert.are.equals(200, status)
    assert.are.equals("text/html", headers["content-type"])
    -- TODO should there be a Cache-Control header?
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
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
  it("the response contains a default PNG image", function()
    assert.are.equals(200, status)
    assert.are.equals("image/png", headers["content-type"])
    assert.are.equals("no-cache, no-store", headers["cache-control"])
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
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
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
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
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
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
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
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
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
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
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
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
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
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
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
  end)
end)

describe("when logout is invoked and a callback with hint and a post_logout_uri have been configured", function()
  test_support.start_server({
      oidc_opts = {
        discovery = {
          end_session_endpoint = "http://127.0.0.1/end-session",
          ping_end_session_endpoint = "http://127.0.0.1/ping-end-session",
        },
        redirect_after_logout_uri = "http://127.0.0.1/after-logout",
        redirect_after_logout_with_id_token_hint = true,
        post_logout_redirect_uri = "http://www.example.org/",
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
    assert.truthy(string.match(headers["location"], ".*id_token_hint=.*"))
  end)
  it("the redirect contains the post_logout_redirect_uri", function()
    local u = string.lower(test_support.urlescape_for_regex("http://www.example.org/"))
    assert.truthy(string.match(string.lower(headers["location"]),
                               ".*post_logout_redirect_uri=" .. u))
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
  end)
end)

describe("when logout is invoked and discovery contains end_session_endpoint and a post_logout_uri have been configured", function()
  test_support.start_server({
      oidc_opts = {
        discovery = {
          end_session_endpoint = "http://127.0.0.1/end-session",
          ping_end_session_endpoint = "http://127.0.0.1/ping-end-session",
        },
        redirect_after_logout_with_id_token_hint = true,
        post_logout_redirect_uri = "http://www.example.org/",
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
  it("the redirect contains the post_logout_redirect_uri", function()
    local u = string.lower(test_support.urlescape_for_regex("http://www.example.org/"))
    assert.truthy(string.match(string.lower(headers["location"]),
                               ".*post_logout_redirect_uri=" .. u))
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
  end)
end)

describe("when logout is invoked and discovery contains ping_end_session_endpoint and a post_logout_uri have been configured", function()
  test_support.start_server({
      oidc_opts = {
        discovery = {
          ping_end_session_endpoint = "http://127.0.0.1/ping-end-session",
        },
        post_logout_redirect_uri = "http://www.example.org/",
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
  it("the redirect contains the post_logout_redirect_uri", function()
    local u = string.lower(test_support.urlescape_for_regex("http://www.example.org/"))
    assert.truthy(string.match(string.lower(headers["location"]),
                               ".*targetresource=" .. u))
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
  end)
end)

describe("when revoke_tokens_on_logout is enabled and a valid revocation endpoint is supplied with auth method client_secret_basic", function()
  test_support.start_server({
    oidc_opts = {
      revoke_tokens_on_logout = true,
      discovery = {
        revocation_endpoint = "http://127.0.0.1/revocation",
        token_endpoint_auth_methods_supported = { "foo", "client_secret_post", "client_secret_basic" }
      },
      token_endpoint_auth_method = "client_secret_basic"
    }
  })
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
  end)

  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
  end)

  it("authorization credentials have not been passed on as post parameters to the revocation endpoint", function()
    assert.is_not.error_log_contains("Received revocation request: .*client_id")
  end)

  it("authorization header has been passed on to the revocation endpoint", function()
    assert.error_log_contains("revocation authorization header: Basic .+")
  end)

  it("token to be revoked has been passed on as a post parameter to the revocation endpoint", function()
    assert.error_log_contains("Received revocation request: .*token=.+")
  end)

  it("debug messages concerning successful revocation have been logged", function()
    assert.error_log_contains("revocation of refresh_token successful")
    assert.error_log_contains("revocation of access_token successful")
  end)
end)

describe("when revoke_tokens_on_logout is enabled and a valid revocation endpoint is supplied with auth method client_secret_post", function()
  test_support.start_server({
    oidc_opts = {
      revoke_tokens_on_logout = true,
      discovery = {
        revocation_endpoint = "http://127.0.0.1/revocation",
        token_endpoint_auth_methods_supported = { "foo", "client_secret_basic", "client_secret_post" }
      },
      token_endpoint_auth_method = "client_secret_post"
    }
  })
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
  end)

  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
  end)

  it("authorization header has not been passed on to the revocation endpoint", function()
    assert.is_not.error_log_contains("revocation authorization header: Basic")
  end)

  it("authorization credentials have been passed on as post parameters to the revocation endpoint", function()
    assert.error_log_contains("Received revocation request: .*client_id=.+")
  end)

  it("token to be revoked has been passed on as a post parameter to the revocation endpoint", function()
    assert.error_log_contains("Received revocation request: .*token=.+")
  end)

  it("debug messages concerning successful revocation have been logged", function()
    assert.error_log_contains("revocation of refresh_token successful")
    assert.error_log_contains("revocation of access_token successful")
  end)
end)

describe("when revoke_tokens_on_logout is enabled and an invalid revocation endpoint is supplied", function()
  test_support.start_server({
    oidc_opts = {
      revoke_tokens_on_logout = true,
      discovery = {
        revocation_endpoint = "http://127.0.0.1/invalid_revocation"
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
  it("the response still contains a default HTML-page", function()
    assert.are.equals(200, status)
    assert.are.equals("text/html", headers["content-type"])
  end)

  it("the session cookie still has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
  end)

  it("error messages concerning unseccussful revocation have been logged", function()
    assert.error_log_contains("revocation of refresh_token unsuccessful")
    assert.error_log_contains("revocation of access_token unsuccessful")
  end)
end)

describe("when revoke_tokens_on_logout is enabled but no revocation endpoint is supplied", function()
  test_support.start_server({
    oidc_opts = {
      revoke_tokens_on_logout = true,
      discovery = {
        revocation_endpoint = nil
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
  it("the response still contains a default HTML-page", function()
    assert.are.equals(200, status)
    assert.are.equals("text/html", headers["content-type"])
  end)

  it("the session cookie still has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
  end)

  it("debug messages concerning unseccussful revocation have been logged", function()
    assert.error_log_contains("no revocation endpoint supplied. unable to revoke refresh_token")
    assert.error_log_contains("no revocation endpoint supplied. unable to revoke access_token")
  end)
end)

describe("when revoke_tokens_on_logout is not defined and a revocation_endpoint is given", function()
  test_support.start_server({
    oidc_opts = {
      revoke_tokens_on_logout = nil,
      discovery = {
        revocation_endpoint = "http://127.0.0.1/revocation"
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
  it("the response still contains a default HTML-page", function()
    assert.are.equals(200, status)
    assert.are.equals("text/html", headers["content-type"])
  end)

  it("the session cookie still has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
  end)

  it("no messages concerning revocation have been logged", function()
    assert.is_not.error_log_contains("revocation")
    assert.is_not.error_log_contains("revoke")
  end)
end)

describe("when the configured logout uri is invoked with no active session", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
                                            url = "http://127.0.0.1/default/logout",
                                            redirect = false
                                          })
  it("the response contains a default HTML-page", function()
    assert.are.equals(200, status)
    assert.are.equals("text/html", headers["content-type"])
    -- TODO should there be a Cache-Control header?
  end)
  it("the session cookie has been revoked", function()
    assert.is.Nil(headers["set-cookie"])
  end)
end)

describe("when logout is invoked and a callback with client id has been configured", function()
  test_support.start_server({
      oidc_opts = {
        discovery = {
          end_session_endpoint = "http://127.0.0.1/end-session",
          ping_end_session_endpoint = "http://127.0.0.1/ping-end-session",
        },
        redirect_after_logout_uri = "http://127.0.0.1/after-logout",
        redirect_after_logout_with_id_token_hint = false,
        redirect_after_logout_with_client_id = true,
        client_id = "client_id",
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
  it("the redirect contains the client_id", function()
    assert.truthy(string.match(headers["location"], ".*%?client_id=.*"))
  end)
  it("the session cookie has been revoked", function()
    assert.truthy(string.match(headers["set-cookie"],
            "session=; Path=/; SameSite=Lax; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT; .*"))
  end)
end)
