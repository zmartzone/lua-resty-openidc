local http = require("socket.http")
local test_support = require("test_support")
require 'busted.runner'()

describe("if refresh_session_interval has not expired", function()
  test_support.start_server({
    oidc_opts = {
      refresh_session_interval = 1
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
end)

describe("if refresh_session_interval has expired", function()
  test_support.start_server({
    oidc_opts = {
      refresh_session_interval = 1
    }
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  os.execute("sleep 2")
  local _, status, headers = http.request({
    url = "http://localhost/default/t",
    redirect = false,
    headers = { cookie = cookies },
  })
  it("a redirect occurs on the next call", function()
    assert.are.equals(302, status)
  end)
  it("the redirect uses the prompt parameter", function()
    assert.truthy(string.match(headers["location"], ".*prompt=none.*"))
  end)
end)
