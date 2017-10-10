local http = require("socket.http")
require 'busted.runner'()

describe("when invoking the hello, world endpoint", function()
  local body = http.request("http://localhost/t")
  it("should return hello, world", function()
    assert.are.equals("hello, world!\n", body)
  end)
end)
