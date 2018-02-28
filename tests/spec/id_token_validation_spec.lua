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
 
describe("when the id_token obtained from the token endpoint contains an iat claim in the future",
         function()
  test_support.start_server({
    id_token = { iat = os.time() + 3600 }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login has failed", function()
    assert.are.equals(401, status)
  end)
  it("an error message has been logged", function()
    assert.error_log_contains("id_token not yet valid")
  end)
end)

describe("when the id_token obtained from the token endpoint contains an iat claim in the future but slack is big enough",
         function()
  test_support.start_server({
    id_token = { iat = os.time() + 120 },
    oidc_opts = { iat_slack = 300 }
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
    -- this is the error message from lua-resty-jwt rather than our
    -- own as its verification comes first
    assert.error_log_contains("'exp' claim expired at")
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

describe("when the id token signature key isn't part of the JWK", function()
  test_support.start_server({
    jwt_verify_secret = "secret",
    token_header = {
      alg = "HS256",
    }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login has failed", function()
    assert.are.equals(401, status)
  end)
  it("an error message has been logged", function()
    assert.error_log_contains("signature mismatch")
  end)
end)

describe("when the id token signature uses a symmetric algorithm", function()
  test_support.start_server({
    jwt_verify_secret = "client_secret",
    token_header = {
      alg = "HS256",
    },
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login succeeds", function()
    assert.are.equals(302, status)
  end)
end)

describe("when the id claims to be signed by an unsupported algorithm", function()
  test_support.start_server({
    fake_id_token_signature = "true",
    oidc_opts = {
      discovery = {
        id_token_signing_alg_values_supported = { "AB256" }
      }
    }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login succeeds", function()
    assert.are.equals(302, status)
  end)
  it("an error is logged", function()
    assert.error_log_contains("ignored id_token signature as algorithm 'AB256' is not supported")
  end)
end)

describe("when the id token signature is invalid", function()
  test_support.start_server({
    break_id_token_signature = "true"
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login has failed", function()
    assert.are.equals(401, status)
  end)
  it("an error message has been logged", function()
    assert.error_log_contains("id_token 'RS256' signature verification failed")
  end)
  it("authenticate returns an error", function()
    assert.error_log_contains("authenticate failed: jwt signature verification failed")
  end)
end)

describe("when the id token signature uses the 'none' alg", function()
  describe("and we are not willing to accept the none alg", function()
    test_support.start_server({
      none_alg_id_token_signature = "true",
    })
    teardown(test_support.stop_server)
    local _, status = test_support.login()
    it("login has failed", function()
      assert.are.equals(401, status)
    end)
    it("an error message has been logged", function()
      assert.error_log_contains("id_token 'none' signature verification failed")
    end)
    it("authenticate returns an error", function()
      assert.error_log_contains("authenticate failed: token uses \"none\" alg but accept_none_alg is not enabled")
    end)
  end)
  describe("and we are willing to accept the none alg", function()
    test_support.start_server({
      none_alg_id_token_signature = "true",
      oidc_opts = {
        accept_none_alg = true,
      }
    })
    teardown(test_support.stop_server)
    local _, status = test_support.login()
    it("login succeeds", function()
      assert.are.equals(302, status)
    end)
    it("an message has been logged", function()
      assert.error_log_contains("accept JWT with alg \"none\" and no signature")
    end)
  end)
end)

describe("when the id token is signed by an algorithm not announced by discovery endpoint", function()
  test_support.start_server({
    oidc_opts = {
      discovery = {
        id_token_signing_alg_values_supported = { "HS256" }
      }
    }
  })
  teardown(test_support.stop_server)
  local _, status = test_support.login()
  it("login has failed", function()
    assert.are.equals(401, status)
  end)
  it("an error message has been logged", function()
    assert.error_log_contains("token is signed by unexpected algorithm \"RS256\"")
  end)
  it("authenticate returns an error", function()
    assert.error_log_contains("authenticate failed: token is signed by unexpected algorithm \"RS256\"")
  end)
end)

