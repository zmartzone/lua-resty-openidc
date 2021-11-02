local http = require('socket.http')
local test_support = require('test_support')
require 'busted.runner'()

describe('when revoke_tokens is successful', function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        revocation_endpoint = "http://127.0.0.1/revocation",
      }
    }
  })
  teardown(test_support.stop_server)
  local _, _, cookies = test_support.login()
  local content_table = {}
  http.request({
      url = "http://localhost/revoke_tokens",
      headers = { cookie = cookies },
      sink = ltn12.sink.table(content_table)
    })

  it('should return true', function()
    assert.are.equals("revoke-result: true\n", table.concat(content_table))
  end)

  it('should have logged the revocation', function()
    assert.error_log_contains("revocation of refresh_token successful")
    assert.error_log_contains("revocation of access_token successful")
  end)

end)
