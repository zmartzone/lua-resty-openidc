local http = require("socket.http")
local test_support = require("test_support")
require 'busted.runner'()

describe("when the id_token obtained from the token endpoint doesn't contain an iss claim",
         function()
  test_support.start_server({
    remove_id_token_claims = { "iss" }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login has failed", function()
    assert.are.equals(401, status)
  end)
  it("an error message has been logged", function()
    assert.error_log_contains("in id_token is not equal to the issuer from the discovery document")
  end)
end)

describe("when the id_token obtained from the token endpoint contains a bad iss claim",
         function()
  test_support.start_server({
    id_token = { iss = "not localhost" }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login has failed", function()
    assert.are.equals(401, status)
  end)
  it("an error message has been logged", function()
    assert.error_log_contains("in id_token is not equal to the issuer from the discovery document")
  end)
end)

describe("when the id_token obtained from the token endpoint doesn't contain a sub claim",
         function()
  pending("need to add support for removing claims")
  test_support.start_server({
    remove_id_token_claims = { "sub" }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login has failed", function()
    assert.are.equals(401, status)
  end)
  it("an error message has been logged", function()
    assert.error_log_contains("no \"sub\" claim found in id_token")
  end)
end)

describe("when the id_token obtained from the token endpoint contains a bad nonce claim",
         function()
  test_support.start_server()
  teardown(test_support.stop_server)
  local _, _, headers = http.request({
    url = "http://localhost/default/t",
    redirect = false
  })
  local state = test_support.grab(headers, 'state')
  test_support.register_nonce({location= "nonce=bad"})
  _, status, _ = http.request({
        url = "http://localhost/default/redirect_uri?code=foo&state=" .. state,
        headers = { cookie = test_support.extract_cookies(headers) },
        redirect = false
  })
  it("login has failed", function()
    assert.are.equals(401, status)
  end)
  it("an error message has been logged", function()
    assert.error_log_contains("in id_token is not equal to the nonce that was sent in the request")
  end)
end)

describe("when the id_token obtained from the token endpoint doesn't contain an iat claim",
         function()
  test_support.start_server({
    remove_id_token_claims = { "iat" }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login has failed", function()
    assert.are.equals(401, status)
  end)
  it("an error message has been logged", function()
    assert.error_log_contains("no \"iat\" claim found in id_token")
  end)
end)

describe("when the id_token obtained from the token endpoint contains a very old iat claim",
         function()
  test_support.start_server({
    id_token = { iat = os.time() - 3600 }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login has failed", function()
    assert.are.equals(401, status)
  end)
  it("an error message has been logged", function()
    assert.error_log_contains("token has been issued too long ago")
  end)
end)

describe("when the id_token obtained from the token endpoint contains a very old iat claim but slack is big enough",
         function()
  test_support.start_server({
    id_token = { iat = os.time() - 3600 },
    oidc_opts = { iat_slack = 3700 }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login succeeds", function()
    assert.are.equals(302, status)
  end)
end)


describe("when the id_token obtained from the token endpoint has expired",
         function()
  test_support.start_server({
    id_token = { exp = os.time() - 300 }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login has failed", function()
    assert.are.equals(401, status)
  end)
  it("an error message has been logged", function()
    assert.error_log_contains("token expired")
  end)
end)

describe("when the id_token obtained from the token endpoint seems to have expired but slack is big enough",
         function()
  test_support.start_server({
    id_token = { exp = os.time() - 300 },
    oidc_opts = { iat_slack = 400 }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login succeeds", function()
    assert.are.equals(302, status)
  end)
end)

describe("when the id_token obtained from the token endpoint doesn't contain an aud claim",
         function()
  test_support.start_server({
    remove_id_token_claims = { "aud" }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login has failed", function()
    assert.are.equals(401, status)
  end)
  it("an error message has been logged", function()
    assert.error_log_contains("no \"aud\" claim found in id_token")
  end)
end)

describe("when the scalar value aud claim of the id_token obtained from the token endpoint doesn't contain client_id",
         function()
  test_support.start_server({
    id_token = { aud = "not client_id" }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login has failed", function()
    assert.are.equals(401, status)
  end)
  it("an error message has been logged", function()
    assert.error_log_contains("token audience does not match")
  end)
end)

describe("when the array value aud claim of the id_token obtained from the token endpoint doesn't contain client_id",
         function()
  test_support.start_server({
    id_token = { aud = { "foo", "not client_id" } }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login has failed", function()
    assert.are.equals(401, status)
  end)
  it("an error message has been logged", function()
    assert.error_log_contains("no match found token audience array")
  end)
end)

describe("when the array value aud claim of the id_token obtained from the token endpoint contains client_id",
         function()
  test_support.start_server({
    id_token = { aud = { "foo", "client_id" } }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login succeeds", function()
    assert.are.equals(302, status)
  end)
end)
