local http = require("socket.http")
local ltn12 = require("ltn12")
local test_support = require("test_support")
require 'busted.runner'()

describe("when session startup returns no session", function()
  test_support.start_server({
    session_start_fails = true,
  })
  teardown(test_support.stop_server)

  local response_body = {}
  local _, status = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false,
    sink = ltn12.sink.table(response_body),
  })

  it("returns the startup error without authenticating the request", function()
    assert.are.equals(401, status)
    assert.truthy(string.find(table.concat(response_body), "session start failed", 1, true))
  end)
end)

describe("when revocation_fail_mode is closed and the revocation store read fails", function()
  test_support.start_server({
    revocation_test = {
      fail_mode = "closed",
      get_fails_after = 1,
    },
  })
  teardown(test_support.stop_server)

  local _, _, cookie = test_support.login()

  local response_body = {}
  local _, status = http.request({
    url = "http://127.0.0.1/default/t",
    headers = { cookie = cookie },
    redirect = false,
    sink = ltn12.sink.table(response_body),
  })
  local body = table.concat(response_body)

  it("propagates the session start failure", function()
    assert.are.equals(401, status)
    assert.truthy(string.find(body, "unable to check session revocation", 1, true))
  end)

  it("does not authenticate the request", function()
    assert.is_nil(string.find(body, "hello, world!", 1, true))
  end)
end)

describe("when revocation_fail_mode is open and the revocation store read fails", function()
  test_support.start_server({
    revocation_test = {
      fail_mode = "open",
      get_fails_after = 1,
    },
  })
  teardown(test_support.stop_server)

  local _, _, cookie = test_support.login()

  local response_body = {}
  local _, status = http.request({
    url = "http://127.0.0.1/default/t",
    headers = { cookie = cookie },
    redirect = false,
    sink = ltn12.sink.table(response_body),
  })

  it("authenticates the request", function()
    assert.are.equals(200, status)
    assert.truthy(string.find(table.concat(response_body), "hello, world!", 1, true))
  end)
end)

describe("when revocation_fail_mode is closed and the revocation store is unreachable during logout", function()
  test_support.start_server({
    revocation_test = {
      fail_mode = "closed",
      set_fails = true,
    },
  })
  teardown(test_support.stop_server)

  local _, _, cookie = test_support.login()

  local response_body = {}
  local _, status = http.request({
    url = "http://127.0.0.1/default/logout",
    headers = { cookie = cookie },
    redirect = false,
    sink = ltn12.sink.table(response_body),
  })
  local body = table.concat(response_body)

  it("propagates destroy failure", function()
    assert.are.equals(401, status)
    assert.truthy(string.find(body, "unable to mark session revoked", 1, true))
  end)

  it("leaves the session valid for replay", function()
    local _, replay_status = http.request({
      url = "http://127.0.0.1/default/t",
      headers = { cookie = cookie },
      redirect = false,
    })
    assert.are.equals(200, replay_status)
  end)
end)

describe("when revocation_fail_mode is open and the revocation store is unreachable during logout", function()
  test_support.start_server({
    revocation_test = {
      fail_mode = "open",
      set_fails = true,
    },
  })
  teardown(test_support.stop_server)

  local _, _, cookie = test_support.login()

  local _, status = http.request({
    url = "http://127.0.0.1/default/logout",
    headers = { cookie = cookie },
    redirect = false,
  })

  it("logout still completes", function()
    assert.are.equals(200, status)
  end)
end)
