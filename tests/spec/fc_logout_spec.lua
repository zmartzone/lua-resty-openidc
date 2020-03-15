local http = require("socket.http")
local test_support = require("test_support")
local ltn12 = require("ltn12")
require 'busted.runner'()

describe('when front_channel_logout URI is invoked with session and all parameters', function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = 'http://127.0.0.1/fc-logout?iss=http%3A%2F%2F127.0.0.1%2F&sid=test_sid',
      headers = { cookie = cookie },
      redirect = false
  })
  it('the response contains a default HTML-page', function()
    assert.are.equals(200, status)
    assert.are.equals('text/html', headers['content-type'])
  end)
  it('the response prohibits caching', function()
    assert.are.equals('no-cache', headers['pragma'])
    assert.are.equals('no-cache, no-store', headers['cache-control'])
  end)
  it('the session cookie has been revoked', function()
    assert.truthy(string.match(headers['set-cookie'],
                               'session=; Expires=Thu, 01 Jan 1970 00:00:01 GMT.*'))
  end)
end)

describe('when front_channel_logout URI is invoked without session', function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = 'http://127.0.0.1/fc-logout?iss=http%3A%2F%2F127.0.0.1%2F&sid=test_sid',
      redirect = false
  })
  it('the response contains a default HTML-page', function()
    assert.are.equals(200, status)
    assert.are.equals('text/html', headers['content-type'])
  end)
  it('the response prohibits caching', function()
    assert.are.equals('no-cache', headers['pragma'])
    assert.are.equals('no-cache, no-store', headers['cache-control'])
  end)
  it('nothing happens to the session cookie', function()
    assert.falsy(headers['set-cookie'])
  end)
  it('a useful error message is logged', function()
    assert.error_log_contains('no session present')
  end)
end)

describe('when front_channel_logout URI is invoked without id_token in session', function()
  test_support.start_server({ oidc_opts = { session_contents = { id_token = false } } })
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = 'http://127.0.0.1/fc-logout?iss=http%3A%2F%2F127.0.0.1%2F&sid=test_sid',
      headers = { cookie = cookie },
      redirect = false
  })
  it('the response contains a default HTML-page', function()
    assert.are.equals(200, status)
    assert.are.equals('text/html', headers['content-type'])
  end)
  it('the response prohibits caching', function()
    assert.are.equals('no-cache', headers['pragma'])
    assert.are.equals('no-cache, no-store', headers['cache-control'])
  end)
  it('nothing happens to the session cookie', function()
    assert.falsy(headers['set-cookie'])
  end)
  it('a useful error message is logged', function()
    assert.error_log_contains('id_token is not stored in session')
  end)
end)

describe('when front_channel_logout URI is invoked without iss', function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = 'http://127.0.0.1/fc-logout?sid=test_sid',
      headers = { cookie = cookie },
      redirect = false
  })
  it('the response contains a default HTML-page', function()
    assert.are.equals(200, status)
    assert.are.equals('text/html', headers['content-type'])
  end)
  it('the response prohibits caching', function()
    assert.are.equals('no-cache', headers['pragma'])
    assert.are.equals('no-cache, no-store', headers['cache-control'])
  end)
  it('nothing happens to the session cookie', function()
    assert.falsy(headers['set-cookie'])
  end)
  it('a useful error message is logged', function()
    assert.error_log_contains('required session information is missing')
  end)
end)

describe('when front_channel_logout URI is invoked with bad iss', function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = 'http://127.0.0.1/fc-logout?iss=http%3A%2F%2F127.0.0.2%2F&sid=test_sid',
      headers = { cookie = cookie },
      redirect = false
  })
  it('the response contains a default HTML-page', function()
    assert.are.equals(200, status)
    assert.are.equals('text/html', headers['content-type'])
  end)
  it('the response prohibits caching', function()
    assert.are.equals('no-cache', headers['pragma'])
    assert.are.equals('no-cache, no-store', headers['cache-control'])
  end)
  it('nothing happens to the session cookie', function()
    assert.falsy(headers['set-cookie'])
  end)
  it('a useful error message is logged', function()
    assert.error_log_contains('iss argument is different from iss stored in id_token')
  end)
end)

describe('when front_channel_logout URI is invoked without sid', function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = 'http://127.0.0.1/fc-logout?iss=http%3A%2F%2F127.0.0.1%2F',
      headers = { cookie = cookie },
      redirect = false
  })
  it('the response contains a default HTML-page', function()
    assert.are.equals(200, status)
    assert.are.equals('text/html', headers['content-type'])
  end)
  it('the response prohibits caching', function()
    assert.are.equals('no-cache', headers['pragma'])
    assert.are.equals('no-cache, no-store', headers['cache-control'])
  end)
  it('nothing happens to the session cookie', function()
    assert.falsy(headers['set-cookie'])
  end)
  it('a useful error message is logged', function()
    assert.error_log_contains('required session information is missing')
  end)
end)

describe('when front_channel_logout URI is invoked with bad sid', function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local _, status, headers = http.request({
      url = 'http://127.0.0.1/fc-logout?iss=http%3A%2F%2F127.0.0.1%2F&sid=test_sid2',
      headers = { cookie = cookie },
      redirect = false
  })
  it('the response contains a default HTML-page', function()
    assert.are.equals(200, status)
    assert.are.equals('text/html', headers['content-type'])
  end)
  it('the response prohibits caching', function()
    assert.are.equals('no-cache', headers['pragma'])
    assert.are.equals('no-cache, no-store', headers['cache-control'])
  end)
  it('nothing happens to the session cookie', function()
    assert.falsy(headers['set-cookie'])
  end)
  it('a useful error message is logged', function()
    assert.error_log_contains('sid argument is different from sid stored in id_token')
  end)
end)

describe('when no session is required', function()
  describe('and no id_token is present', function()
    test_support.start_server({
        oidc_opts = { session_contents = { id_token = false } },
        fc_logout_opts = { session_required = false }
    })
    teardown(test_support.stop_server)
    local _, _, cookie = test_support.login()
    local _, status, headers = http.request({
        url = 'http://127.0.0.1/fc-logout?iss=http%3A%2F%2F127.0.0.1%2F&sid=test_sid',
        headers = { cookie = cookie },
        redirect = false
    })
    it('the response contains a default HTML-page', function()
         assert.are.equals(200, status)
         assert.are.equals('text/html', headers['content-type'])
    end)
    it('the response prohibits caching', function()
         assert.are.equals('no-cache', headers['pragma'])
         assert.are.equals('no-cache, no-store', headers['cache-control'])
    end)
    it('the session cookie has been revoked', function()
         assert.truthy(string.match(headers['set-cookie'],
                                    'session=; Expires=Thu, 01 Jan 1970 00:00:01 GMT.*'))
    end)
  end)
  describe('and session parameters are missing', function()
    test_support.start_server({
        fc_logout_opts = { session_required = false }
    })
    teardown(test_support.stop_server)
    local _, _, cookie = test_support.login()
    local _, status, headers = http.request({
        url = 'http://127.0.0.1/fc-logout',
        headers = { cookie = cookie },
        redirect = false
    })
    it('the response contains a default HTML-page', function()
         assert.are.equals(200, status)
         assert.are.equals('text/html', headers['content-type'])
    end)
    it('the response prohibits caching', function()
         assert.are.equals('no-cache', headers['pragma'])
         assert.are.equals('no-cache, no-store', headers['cache-control'])
    end)
    it('the session cookie has been revoked', function()
         assert.truthy(string.match(headers['set-cookie'],
                                    'session=; Expires=Thu, 01 Jan 1970 00:00:01 GMT.*'))
    end)
  end)
  describe('and opts.iss matches iss parameter', function()
    test_support.start_server({
        oidc_opts = { session_contents = { id_token = false } },
        fc_logout_opts = { session_required = false, iss = 'http://127.0.0.1/' }
    })
    teardown(test_support.stop_server)
    local _, _, cookie = test_support.login()
    local _, status, headers = http.request({
        url = 'http://127.0.0.1/fc-logout?iss=http%3A%2F%2F127.0.0.1%2F&sid=test_sid',
        headers = { cookie = cookie },
        redirect = false
    })
    it('the response contains a default HTML-page', function()
         assert.are.equals(200, status)
         assert.are.equals('text/html', headers['content-type'])
    end)
    it('the response prohibits caching', function()
         assert.are.equals('no-cache', headers['pragma'])
         assert.are.equals('no-cache, no-store', headers['cache-control'])
    end)
    it('the session cookie has been revoked', function()
         assert.truthy(string.match(headers['set-cookie'],
                                    'session=; Expires=Thu, 01 Jan 1970 00:00:01 GMT.*'))
    end)
  end)
  describe('and opts.iss is present but parameter is differemt', function()
    test_support.start_server({
        oidc_opts = { session_contents = { id_token = false } },
        fc_logout_opts = { session_required = false, iss = 'http://127.0.0.1/' }
    })
    teardown(test_support.stop_server)
    local _, _, cookie = test_support.login()
    local _, status, headers = http.request({
        url = 'http://127.0.0.1/fc-logout?iss=http%3A%2F%2F127.0.0.2%2F&sid=test_sid',
        headers = { cookie = cookie },
        redirect = false
    })
    it('the response contains a default HTML-page', function()
         assert.are.equals(200, status)
         assert.are.equals('text/html', headers['content-type'])
    end)
    it('the response prohibits caching', function()
         assert.are.equals('no-cache', headers['pragma'])
         assert.are.equals('no-cache, no-store', headers['cache-control'])
    end)
    it('nothing happens to the session cookie', function()
         assert.falsy(headers['set-cookie'])
    end)
    it('a useful error message is logged', function()
         assert.error_log_contains('iss argument is different from iss stored in opts')
    end)
  end)
end)

describe('when a single downstream logout URI is configured', function()
  test_support.start_server({
      fc_logout_opts = { downstream_logout = '/downstream' }
  })
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local content_table = {}
  local _, status, headers = http.request({
      url = 'http://127.0.0.1/fc-logout?iss=http%3A%2F%2F127.0.0.1%2F&sid=test_sid',
      headers = { cookie = cookie },
      redirect = false,
      sink = ltn12.sink.table(content_table)
  })
  it('the response contains an iframe for downstream', function()
    assert.truthy(string.match(table.concat(content_table), '<iframe src="/downstream"'))
  end)
end)

describe('when a multiple downstream logout URIs are configured', function()
  test_support.start_server({
      fc_logout_opts = { downstream_logout = { '/downstream1', '/downstream2' } }
  })
  teardown(test_support.stop_server)
  local _, _, cookie = test_support.login()
  local content_table = {}
  local _, status, headers = http.request({
      url = 'http://127.0.0.1/fc-logout?iss=http%3A%2F%2F127.0.0.1%2F&sid=test_sid',
      headers = { cookie = cookie },
      redirect = false,
      sink = ltn12.sink.table(content_table)
  })
  it('the response contains an iframe for downstream', function()
    assert.truthy(string.match(table.concat(content_table), '<iframe src="/downstream1"'))
    assert.truthy(string.match(table.concat(content_table), '<iframe src="/downstream2"'))
  end)
end)
