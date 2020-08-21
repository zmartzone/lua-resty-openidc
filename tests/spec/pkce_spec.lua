local http = require('socket.http')
local test_support = require('test_support')
require 'busted.runner'()

describe('when pkce is disabled in authorize request', function()
  test_support.start_server()
  teardown(test_support.stop_server)

  local _, status, headers = http.request({
    url = 'http://127.0.0.1/default/t',
    redirect = false
  })
  it('there is no code_challenge parameter', function()
    assert.falsy(string.match(headers['location'], '.*code_challenge=.*'))
  end)
  it('there is no code_challenge_method parameter', function()
    assert.falsy(string.match(headers['location'], '.*code_challenge_method=.*'))
  end)
end)

describe('when pkce is enabled in authorize request', function()
  test_support.start_server({oidc_opts = { use_pkce = true } })
  teardown(test_support.stop_server)

  local _, status, headers = http.request({
    url = 'http://127.0.0.1/default/t',
    redirect = false
  })
  it('there is a code_challenge parameter', function()
    assert.truthy(string.match(headers['location'], '.*code_challenge=.*'))
  end)
  it('there is a S256 code_challenge_method parameter', function()
    assert.truthy(string.match(headers['location'], '.*code_challenge_method=S256.*'))
  end)
end)

local function assert_token_endpoint_call_contains(s, case_insensitive)
   assert.error_log_contains("Received token request: .*" ..  s .. ".*",
                             case_insensitive)
end

local function assert_token_endpoint_call_doesnt_contain(s, case_insensitive)
   assert.is_not.error_log_contains("Received token request: .*" ..  s .. ".*",
                                    case_insensitive)
end

describe('when pkce is disabled and the token endpoint is invoked', function()
  test_support.start_server()
  teardown(test_support.stop_server)
  test_support.login()
  it("the request doesn't contain a code_verifier", function()
    assert_token_endpoint_call_doesnt_contain('.*code_verifier=.*')
  end)
end)

describe('when pkce is enabled and the token endpoint is invoked', function()
  test_support.start_server({oidc_opts = { use_pkce = true } })
  teardown(test_support.stop_server)

  local _, _, headers = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false
  })
  local state = test_support.grab(headers, 'state')
  local code_challenge = test_support.grab(headers, 'code_challenge')
  test_support.register_nonce(headers)
  http.request({
        url = "http://127.0.0.1/default/redirect_uri?code=foo&state=" .. state,
        headers = { cookie = test_support.extract_cookies(headers) },
        redirect = false
  })

  local log = test_support.load("/tmp/server/logs/error.log")
  local code_verifier = log:match('Received token request: .*code_verifier=([^&]-)[&,]')
  it('the request contains a code_verifier', function()
    assert.truthy(code_verifier)
  end)
  it('hashing the code verifier leads to the challenge', function()
    local as_base64 = function(s)
      local rem = #s % 4
      if rem > 0 then
        s = s .. string.rep('=', 4 - rem)
      end
      return s:gsub('%-', '+'):gsub('_', '/')
    end
    local challenge = as_base64(code_challenge)
    local hashed_verifier = (require 'mime').b64((require 'sha2').bytes(code_verifier))
    assert.are.equals(hashed_verifier, challenge)
  end)
end)
