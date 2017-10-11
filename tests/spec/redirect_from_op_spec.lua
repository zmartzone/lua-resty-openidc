local http = require("socket.http")
local test_support = require("test_support")
local url = require("socket.url")
require 'busted.runner'()

local function grab_state(headers)
  return string.match(headers.location, ".*state=([^&]+).*")
end

describe("when a redirect is received", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, headers = http.request({
    url = "http://localhost/default/t",
    redirect = false
  })
  local state = grab_state(headers)
  describe("without an active user session", function()
    local _, redirStatus = http.request({
          url = "http://localhost/default/redirect_uri?code=foo&state" .. state,
    })
    it("should be rejected", function()
       assert.are.equals(500, redirStatus)
    end)
    it("will log an error message", function()
      assert.error_log_contains("but there's no session state found")
    end)
  end)
end)
