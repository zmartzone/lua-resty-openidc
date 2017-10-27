local test_support = require("test_support")
require 'busted.runner'()

describe("when the userinfo endpoint is invoked", function()
  test_support.start_server()
  teardown(test_support.stop_server)
  test_support.login()
  it("the access_token is sent as bearer token", function()
    assert.error_log_contains("userinfo authorization header: Bearer ")
  end)
  -- TODO find a way to verify user has been stored in session
end)

describe("when configuration says not to store userinfo", function()
  test_support.start_server({
    oidc_opts = {
      session_contents = {
        user = false
      }
    }
  })
  teardown(test_support.stop_server)
  test_support.login()
  it("the userinfo endpoint is not invoked", function()
    assert.is_not.error_log_contains("userinfo authorization header: Bearer ")
  end)
end)

describe("when the userinfo response doesn't contain a sub claim", function()
  test_support.start_server({
    remove_userinfo_claims = { "sub" }
  })
  teardown(test_support.stop_server)
  test_support.login()
  it("an error message is logged", function()
    assert.error_log_contains("\"sub\" claim in id_token %(\"subject\"%) is not equal to the \"sub\" claim returned from the userinfo endpoint %(\"null\"%)")
  end)
  -- TODO find a way to verify user has not been stored in session
end)

describe("when the userinfo response's sub disagrees with the id_token", function()
  test_support.start_server({
    userinfo = {
      sub = "foo"
    }
  })
  teardown(test_support.stop_server)
  test_support.login()
  it("an error message is logged", function()
    assert.error_log_contains("\"sub\" claim in id_token %(\"subject\"%) is not equal to the \"sub\" claim returned from the userinfo endpoint %(\"foo\"%)")
  end)
  -- TODO find a way to verify user has not been stored in session
end)

