local http = require("socket.http")
local test_support = require("test_support")
local ltn12 = require("ltn12")
require 'busted.runner'()

describe("when response_mode is form_post", function()
  test_support.start_server({oidc_opts = {response_mode = "form_post"}})
  teardown(test_support.stop_server)
  local _, status, headers = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  it("then it is included", function()
    assert.truthy(string.match(headers["location"], ".*response_mode=form_post.*"))
  end)
end)

local function do_post(cookie_header, body)
  local x, y, z = http.request({
      method = "POST",
      url = "http://localhost/default/redirect_uri",
      headers = {
        ["Content-Type"] = "application/x-www-form-urlencoded",
        ["Content-Length"] = string.len(body),
        cookie = cookie_header,
      },
      source = ltn12.source.string(body),
      redirect = false
    })
  return x, y, z
end

describe("when a form_post is received", function()
  test_support.start_server({oidc_opts = {response_mode = "form_post"}})
  teardown(test_support.stop_server)
  local _, _, headers = http.request({
    url = "http://localhost/default/t",
    redirect = false
  })
  local state = test_support.grab(headers, 'state')
  test_support.register_nonce(headers)
  local cookie_header = test_support.extract_cookies(headers)
  describe("without an active user session", function()
    local _, redirStatus = http.request({
        method = 'POST',
        url = "http://localhost/default/redirect_uri",
        headers = {
          ["Content-Type"] = "application/x-www-form-urlencoded",
        },
        source = ltn12.source.string("code=foo&state=" .. state)
    })
    it("should be rejected", function()
       assert.are.equals(401, redirStatus)
    end)
    it("will log an error message", function()
      assert.error_log_contains("but there's no session state found")
    end)
  end)
  describe("with bad state", function()
    local _, redirStatus = do_post(cookie_header, "code=foo&state=X" .. state)
    it("should be rejected", function()
       assert.are.equals(401, redirStatus)
    end)
    it("will log an error message", function()
      assert.error_log_contains("does not match state restored from session")
    end)
  end)
  describe("without state", function()
    local _, redirStatus = do_post(cookie_header, "code=foo")
    it("should be rejected", function()
       assert.are.equals(401, redirStatus)
    end)
    it("will log an error message", function()
      assert.error_log_contains("unhandled request to the redirect_uri")
    end)
  end)
  describe("without code", function()
    local _, redirStatus = do_post(cookie_header, "state=" .. state)
    it("should be rejected", function()
       assert.are.equals(401, redirStatus)
    end)
    it("will log an error message", function()
      assert.error_log_contains("unhandled request to the redirect_uri")
    end)
  end)
  describe("with all things set", function()
    local _, redirStatus, h = do_post(cookie_header, "code=foo&state=" .. state)
    it("redirects to the original URI", function()
       assert.are.equals(302, redirStatus)
       assert.are.equals("/default/t", h.location)
    end)
  end)
end)

