local http = require("socket.http")
local test_support = require("test_support")
local ltn12 = require("ltn12")
require 'busted.runner'()

describe("when accessing the protected resource with opts.prohibit_redirect", function()
  test_support.start_server({
    oidc_opts = { prohibit_redirect = true }
  })
  teardown(test_support.stop_server)
  local content_table = {}
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false,
    sink = ltn12.sink.table(content_table)
  })
  it("returns 401", function()
    assert.are.equals(401, status)
  end)
end)
