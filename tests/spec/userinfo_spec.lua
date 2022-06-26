local test_support = require("test_support")
require 'busted.runner'()

describe("when the userinfo endpoint is invoked", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  test_support.login()
  it("the access_token is sent as bearer token", function()
    assert.error_log_contains("userinfo authorization header: Bearer ")
  end)
  -- TODO find a way to verify user has been stored in session
end)

describe("when configuration says not to store userinfo", function()
  test_support.start_server({
    oidc_opts = {
      session_contents = {
        user = false
      }
    }
  })
  teardown(test_support.stop_server)
  test_support.login()
  it("the userinfo endpoint is not invoked", function()
    assert.is_not.error_log_contains("userinfo authorization header: Bearer ")
  end)
end)

describe("when the userinfo response doesn't contain a sub claim", function()
  test_support.start_server({
    remove_userinfo_claims = { "sub" }
  })
  teardown(test_support.stop_server)
  test_support.login()
  it("an error message is logged", function()
    assert.error_log_contains("\"sub\" claim in id_token %(\"subject\"%) is not equal to the \"sub\" claim returned from the userinfo endpoint %(\"null\"%)")
  end)
  -- TODO find a way to verify user has not been stored in session
end)

describe("when the userinfo response's sub disagrees with the id_token", function()
  test_support.start_server({
    userinfo = {
      sub = "foo"
    }
  })
  teardown(test_support.stop_server)
  test_support.login()
  it("an error message is logged", function()
    assert.error_log_contains("\"sub\" claim in id_token %(\"subject\"%) is not equal to the \"sub\" claim returned from the userinfo endpoint %(\"foo\"%)")
  end)
  -- TODO find a way to verify user has not been stored in session
end)

describe("when userinfo endpoint is not resolvable", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        userinfo_endpoint = "http://foo.example.org/"
      }
    },
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login succeeds", function()
    assert.are.equals(302, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains(".*foo.example.org could not be resolved.*")
  end)
end)

describe("when userinfo endpoint is not reachable", function()
  test_support.start_server({
    oidc_opts = {
      timeout = 40000,
      discovery = {
        userinfo_endpoint = "http://192.0.2.1/"
      }
    },
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login succeeds", function()
    assert.are.equals(302, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains(".*error calling userinfo endpoint: accessing %(http://192.0.2.1/%) failed")
  end)
end)

describe("when userinfo endpoint is slow but no timeout is configured", function()
  test_support.start_server({
    delay_response = { userinfo = 1000 },
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login succeeds", function()
    assert.are.equals(302, status)
  end)
end)

describe("when userinfo endpoint is slow and a simple timeout is configured", function()
  test_support.start_server({
    delay_response = { userinfo = 1000 },
    oidc_opts = {
      timeout = 200
    }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login succeeds", function()
    assert.are.equals(302, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains(".*error calling userinfo endpoint: accessing %(http://127.0.0.1/user%-info%) failed: timeout")
  end)
end)

describe("when userinfo endpoint is slow and a table timeout is configured", function()
  test_support.start_server({
    delay_response = { userinfo = 1000 },
    oidc_opts = {
      timeout = { read = 200 }
    }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login succeeds", function()
    assert.are.equals(302, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains(".*error calling userinfo endpoint: accessing %(http://127.0.0.1/user%-info%) failed: timeout")
  end)
end)

describe("when userinfo endpoint sends a 4xx status", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        userinfo_endpoint = "http://127.0.0.1/not-there"
      }
    },
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login succeeds", function()
    assert.are.equals(302, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains(".*response indicates failure, status=404,")
  end)
end)

describe("when userinfo endpoint doesn't return proper JSON", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        userinfo_endpoint = "http://127.0.0.1/t"
      }
    },
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login succeeds", function()
    assert.are.equals(302, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("JSON decoding failed")
  end)
end)
