local http = require("socket.http")
local test_support = require("test_support")
require 'busted.runner'()

local function base_checks()
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  describe("and not sending any Authorization header", function()
    local _, status = http.request({
      url = "http://127.0.0.1/verify_bearer_token"
    })
    it("the token is invalid", function()
      assert.are.equals(401, status)
    end)
    it("an error is logged", function()
      assert.error_log_contains("no Authorization header found")
    end)
  end)
  describe("and sending a valid JWT as bearer token", function()
    local _, status = http.request({
      url = "http://127.0.0.1/verify_bearer_token",
      headers = { authorization = "Bearer " .. jwt }
    })
    it("the token is valid", function()
      assert.are.equals(204, status)
    end)
  end)
  describe("and sending a non Bearer Authorization header", function()
    local _, status = http.request({
      url = "http://127.0.0.1/verify_bearer_token",
      headers = { authorization = "Foo " .. jwt }
    })
    it("an error is logged", function()
      assert.error_log_contains("no Bearer authorization header value found")
    end)
  end)
  describe("and sending something that doesn't look like a JWT at all", function()
    local _, status = http.request({
      url = "http://127.0.0.1/verify_bearer_token",
      headers = { authorization = "Bearer hello world" }
    })
    it("the token is invalid", function()
      assert.are.equals(401, status)
    end)
    it("an error is logged", function()
      assert.error_log_contains("invalid jwt")
    end)
  end)
  describe("and sending a JWT with broken signature", function()
    local _, status = http.request({
      url = "http://127.0.0.1/verify_bearer_token",
      headers = { authorization = "Bearer " ..  jwt:sub(1, -6) .. "XXXXX" }
    })
    it("the token is invalid", function()
      assert.are.equals(401, status)
    end)
    it("an error is logged", function()
      local alternative1 = pcall(assert.error_log_contains, "Verification failed")
      if not alternative1 then
        assert.error_log_contains("signature mismatch")
      end
    end)
  end)
end

describe("when using a statically configured RSA public key", function()
  test_support.start_server({
    verify_opts = {
      secret = test_support.load("/spec/public_rsa_key.pem")
    }
  })
  teardown(test_support.stop_server)
  base_checks()
end)

describe("when using a statically configured symmetric key for HMAC", function()
  test_support.start_server({
    verify_opts = {
      secret = "secret"
    },
    jwt_sign_secret = "secret",
    token_header = {
      alg = "HS256",
    }
  })
  teardown(test_support.stop_server)
  base_checks()
end)

describe("when using a RSA key from a JWK that contains the x5c claim", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = "http://127.0.0.1/jwk",
      }
    }
  })
  teardown(test_support.stop_server)
  base_checks()
end)

describe("when using a RSA key from a JWK that doesn't contain the x5c claim", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = "http://127.0.0.1/jwk",
      }
    },
    jwk = test_support.load("/spec/rsa_key_jwk_with_n_and_e.json")
  })
  teardown(test_support.stop_server)
  base_checks()
end)

describe("when the JWK specifies a kid and the JWKS contains multiple keys", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = "http://127.0.0.1/jwk",
      }
    },
    jwk = test_support.load("/spec/jwks_with_two_keys.json"),
    token_header = {
      kid = "abcd",
    }
  })
  teardown(test_support.stop_server)
  base_checks()
end)

describe("when the JWK specifies no kid and the JWKS contains multiple keys", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = "http://127.0.0.1/jwk",
      }
    },
    jwk = test_support.load("/spec/jwks_with_two_keys.json"),
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the token is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error is logged", function()
    assert.error_log_contains("JWT doesn't specify kid but the keystore contains multiple RSA keys")
  end)
end)

describe("when the access token has expired", function()
  test_support.start_server({
    verify_opts = {
      secret = test_support.load("/spec/public_rsa_key.pem")
    },
    access_token = {
      exp = os.time() - 300
    }
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the token is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error is logged", function()
    -- this is the error message from lua-resty-jwt rather than our
    -- own as its verification comes first
    assert.error_log_contains("'exp' claim expired at")
  end)
end)

describe("when the access token has expired but slack is big enough", function()
  test_support.start_server({
    verify_opts = {
      secret = test_support.load("/spec/public_rsa_key.pem"),
      iat_slack = 400
    },
    access_token = {
      exp = os.time() - 300
    }
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the token is valid", function()
    assert.are.equals(204, status)
  end)
end)

describe("when the access token doesn't contain the exp claim at all", function()
  test_support.start_server({
    verify_opts = {
      secret = test_support.load("/spec/public_rsa_key.pem"),
    },
    remove_access_token_claims = { "exp" },
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the token is valid", function()
    assert.are.equals(204, status)
  end)
end)

describe("when using a JWT not signed but using the 'none' alg", function()
  describe("and we are willing to accept the none alg", function()
    test_support.start_server({
      verify_opts = {
        discovery = {
          jwks_uri = "http://127.0.0.1/jwk",
        },
        accept_none_alg = true,
      },
      jwk = test_support.load("/spec/jwks_with_two_keys.json"),
    })
    teardown(test_support.stop_server)
    local jwt = test_support.self_signed_jwt({
        exp = os.time() + 3600,
    })
    local _, status = http.request({
        url = "http://127.0.0.1/verify_bearer_token",
        headers = { authorization = "Bearer " .. jwt }
    })
    it("the token is valid", function()
      assert.are.equals(204, status)
    end)
  end)
  describe("and we are not willing to accept the none alg", function()
    test_support.start_server({
      verify_opts = {
        discovery = {
          jwks_uri = "http://127.0.0.1/jwk",
        },
      },
      jwk = test_support.load("/spec/jwks_with_two_keys.json"),
    })
    teardown(test_support.stop_server)
    local jwt = test_support.self_signed_jwt({
        exp = os.time() + 3600,
    })
    local _, status = http.request({
        url = "http://127.0.0.1/verify_bearer_token",
        headers = { authorization = "Bearer " .. jwt }
    })
    it("the token is invalid", function()
      assert.are.equals(401, status)
    end)
  end)
end)

describe("when using an unsigned JWT with an alg different from 'none'", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = "http://127.0.0.1/jwk",
      }
    },
    jwk = test_support.load("/spec/jwks_with_two_keys.json"),
  })
  teardown(test_support.stop_server)
  local jwt = test_support.self_signed_jwt({
      exp = os.time() + 3600,
  }, "RS256")
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the token is invalid", function()
    assert.are.equals(401, status)
  end)
end)

describe("when the bearer token doesn't contain JSON but looks like an unsigned token", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = "http://127.0.0.1/jwk",
      }
    },
    jwk = test_support.load("/spec/jwks_with_two_keys.json"),
  })
  teardown(test_support.stop_server)
  local jwt = "foo.bar."
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the token is invalid", function()
    assert.are.equals(401, status)
  end)
end)

describe("when the JWT claims to be signed by an unsupported algorithm", function()
  test_support.start_server({
    fake_access_token_signature = "true"
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
      url = "http://127.0.0.1/verify_bearer_token",
      headers = { authorization = "Bearer " .. jwt }
  })
  it("the token is invalid", function()
    assert.are.equals(401, status)
  end)
end)

describe("when discovery endpoint is not resolvable", function()
  test_support.start_server({
    verify_opts = {
      discovery = "http://foo.example.org/"
    },
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the token is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("Invalid token: accessing discovery url.*foo.example.org could not be resolved.*")
  end)
end)

describe("when jwk endpoint is not resolvable", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = "http://foo.example.org/",
      }
    },
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the token is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("Invalid token: accessing jwks url.*foo.example.org could not be resolved.*")
  end)
end)

describe("when jwks endpoint is not reachable", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = "http://192.0.2.1/"
      }
    },
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("Invalid token: accessing jwks url.*%(http://192.0.2.1/%) failed")
  end)
end)

describe("when jwk endpoint is slow but no timeout is configured", function()
  test_support.start_server({
    delay_response = { jwk = 1000 },
    verify_opts = {
      discovery = {
        jwks_uri = "http://127.0.0.1/jwk",
      }
    }
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the response is valid", function()
    assert.are.equals(204, status)
  end)
end)

describe("when jwk endpoint is slow and a simple timeout is configured", function()
  test_support.start_server({
    delay_response = { jwk = 1000 },
    verify_opts = {
      discovery = {
        jwks_uri = "http://127.0.0.1/jwk",
      },
      timeout = 200,
    },
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("Invalid token: accessing jwks url.*%(http://127.0.0.1/jwk%) failed: timeout")
  end)
end)

describe("when jwk endpoint is slow and a table timeout is configured", function()
  test_support.start_server({
    delay_response = { jwk = 1000 },
    verify_opts = {
      discovery = {
        jwks_uri = "http://127.0.0.1/jwk",
      },
      timeout = { read = 200 },
    },
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("Invalid token: accessing jwks url.*%(http://127.0.0.1/jwk%) failed: timeout")
  end)
end)

describe("when jwks endpoint sends a 4xx status", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = "http://127.0.0.1/not-there"
      }
    },
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("Invalid token:.*response indicates failure, status=404,")
  end)
end)

describe("when jwks endpoint doesn't return proper JSON", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = "http://127.0.0.1/t"
      }
    },
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("Invalid token: JSON decoding failed")
  end)
end)

-- see https://github.com/zmartzone/lua-resty-openidc/issues/124
describe("when the token is signed by an RSA key but discovery doesn't contain jwks_uri", function()
  test_support.start_server({
    verify_opts = {
      discovery = { }
    }
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("Invalid token:.*jwks_uri is not present or not a string")
  end)
end)

-- see https://github.com/zmartzone/lua-resty-openidc/issues/124
describe("when the token is signed by an RSA key but jwks_uri is not a string", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = { }
      }
    }
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("Invalid token:.*jwks_uri is not present or not a string")
  end)
end)

-- see https://github.com/zmartzone/lua-resty-openidc/issues/124
describe("when the token is signed by an RSA key but jwks_uri is empty", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = ""
      }
    }
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("Invalid token:.*jwks_uri is not present or not a string")
  end)
end)

describe("when expecting an RSA signature but token uses HMAC", function()
  test_support.start_server({
    verify_opts = {
      secret = test_support.load("/spec/public_rsa_key.pem"),
      token_signing_alg_values_expected = "RS256"
    },
    jwt_sign_secret = test_support.load("/spec/public_rsa_key.pem"),
    token_header = {
      alg = "HS256",
    }
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  local _, status = http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the response is invalid", function()
    assert.are.equals(401, status)
  end)
  it("an error has been logged", function()
    assert.error_log_contains("Invalid token:.*token is signed by unexpected algorithm \"HS256\"")
  end)
end)

describe("when using a statically configured 4k RSA public key", function()
  test_support.start_server({
    verify_opts = {
      secret = test_support.load("/spec/public_longer_rsa_key.pem")
    },
    jwt_sign_secret = test_support.load("/spec/private_longer_rsa_key.pem")
  })
  teardown(test_support.stop_server)
  base_checks()
end)

describe("when using a 4k RSA key from a JWK that contains the x5c claim", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = "http://127.0.0.1/jwk",
      }
    },
    jwk = test_support.load("/spec/longer_rsa_key_jwk_with_x5c.json"),
    jwt_sign_secret = test_support.load("/spec/private_longer_rsa_key.pem")
  })
  teardown(test_support.stop_server)
  base_checks()
end)

describe("when using a 4k RSA key from a JWK that doesn't contain the x5c claim", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = "http://127.0.0.1/jwk",
      }
    },
    jwk = test_support.load("/spec/longer_rsa_key_jwk_with_n_and_e.json"),
    jwt_sign_secret = test_support.load("/spec/private_longer_rsa_key.pem")
  })
  teardown(test_support.stop_server)
  base_checks()
end)

describe("when a request_decorator has been specified when calling the jwks endpoint", function()
  test_support.start_server({
    verify_opts = {
      discovery = {
        jwks_uri = "http://127.0.0.1/jwk",
      },
      decorate = true
    },
  })
  teardown(test_support.stop_server)
  local jwt = test_support.trim(http.request("http://127.0.0.1/jwt"))
  http.request({
    url = "http://127.0.0.1/verify_bearer_token",
    headers = { authorization = "Bearer " .. jwt }
  })
  it("the request contains the additional parameter", function()
    assert.error_log_contains('jwk uri_args:.*"foo"%s*:%s*"bar"')
  end)
end)
