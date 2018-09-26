local http = require("socket.http")
local test_support = require("test_support")
local ltn12 = require("ltn12")
require 'busted.runner'()

describe("when a redirect is received", function()
  test_support.start_server()
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
          url = "http://localhost/default/redirect_uri?code=foo&state=" .. state,
    })
    it("should be rejected", function()
       assert.are.equals(401, redirStatus)
    end)
    it("will log an error message", function()
      assert.error_log_contains("but there's no session state found")
    end)
  end)
  describe("with bad state", function()
    local _, redirStatus = http.request({
          url = "http://localhost/default/redirect_uri?code=foo&state=X" .. state,
          headers = { cookie = cookie_header }
    })
    it("should be rejected", function()
       assert.are.equals(401, redirStatus)
    end)
    it("will log an error message", function()
      assert.error_log_contains("does not match state restored from session")
    end)
  end)
  describe("without state", function()
    local _, redirStatus = http.request({
          url = "http://localhost/default/redirect_uri?code=foo",
          headers = { cookie = cookie_header }
    })
    it("should be rejected", function()
       assert.are.equals(401, redirStatus)
    end)
    it("will log an error message", function()
      assert.error_log_contains("unhandled request to the redirect_uri")
    end)
  end)
  describe("without code", function()
    local _, redirStatus = http.request({
          url = "http://localhost/default/redirect_uri?state=" .. state,
          headers = { cookie = cookie_header }
    })
    it("should be rejected", function()
       assert.are.equals(401, redirStatus)
    end)
    it("will log an error message", function()
      assert.error_log_contains("unhandled request to the redirect_uri")
    end)
  end)
  describe("with all things set", function()
    local _, redirStatus, h = http.request({
          url = "http://localhost/default/redirect_uri?code=foo&state=" .. state,
          headers = { cookie = cookie_header },
          redirect = false
    })
    it("redirects to the original URI", function()
       assert.are.equals(302, redirStatus)
       assert.are.equals("/default/t", h.location)
    end)
  end)
end)

describe("when the full login has been performed and the initial link is called", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  local content_table = {}
  local _, status, _ = http.request({
    url = "http://localhost/default/t",
    redirect = false,
    headers = { cookie = cookies },
    sink = ltn12.sink.table(content_table)
  })
  it("no redirect occurs", function()
    assert.are.equals(200, status)
  end)
  it("the response is hello, world!", function()
    assert.are.equals("hello, world!\n", table.concat(content_table))
  end)
end)

describe("when the redirect_uri is specified as relative URI", function()
  test_support.start_server({
    oidc_opts = {
      redirect_uri_path = '/default/redirect_uri',
    },
    remove_oidc_config_keys = { 'redirect_uri' },
  })
  teardown(test_support.stop_server)
  local _, _, headers = http.request({
    url = "http://localhost/default/t",
    redirect = false
  })
  local state = test_support.grab(headers, 'state')
  test_support.register_nonce(headers)
  local cookie_header = test_support.extract_cookies(headers)
  describe("accessing the redirect_uri path with good parameters", function()
    local _, redirStatus, h = http.request({
          url = "http://localhost/default/redirect_uri?code=foo&state=" .. state,
          headers = { cookie = cookie_header },
          redirect = false
    })
    it("redirects to the original URI", function()
       assert.are.equals(302, redirStatus)
       assert.are.equals("/default/t", h.location)
    end)
  end)
  it("a deprecation warning is logged", function()
    assert.error_log_contains("using deprecated option `opts.redirect_uri_path` or `opts.redirect_uri_scheme`")
  end)
end)

describe("when the redirect_uri and target-uri are specified as absolute URIs", function()
  test_support.start_server({
    oidc_opts = {
      redirect_uri = 'https://example.com/default-absolute/redirect_uri',
    },
  })
  teardown(test_support.stop_server)
  local _, _, headers = http.request({
    url = "http://localhost/default-absolute/t",
    redirect = false
  })
  local state = test_support.grab(headers, 'state')
  test_support.register_nonce(headers)
  local cookie_header = test_support.extract_cookies(headers)
  describe("accessing the redirect_uri path with good parameters", function()
    local _, redirStatus, h = http.request({
          url = "http://localhost/default-absolute/redirect_uri?code=foo&state=" .. state,
          headers = { cookie = cookie_header },
          redirect = false
    })
    it("redirects to the original URI", function()
       assert.are.equals(302, redirStatus)
       assert.are.equals("http://localhost/default-absolute/t", h.location)
    end)
  end)
end)
