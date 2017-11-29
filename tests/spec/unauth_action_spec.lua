local http = require("socket.http")
local test_support = require("test_support")
local ltn12 = require("ltn12")
require 'busted.runner'()

describe("when accessing the protected resource without unauth_action set to pass", function()
  test_support.start_server({
    unauth_action = "pass"
  })
  teardown(test_support.stop_server)
  local content_table = {}
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false,
    sink = ltn12.sink.table(content_table)
  })
  it("lets the request pass through", function()
    assert.are.equals(200, status)
    assert.are.equals("hello, world!\n", table.concat(content_table))
  end)
  it("but no access token has been provided", function()
    assert.error_log_contains("authenticate didn't return any access token")
  end)
end)
