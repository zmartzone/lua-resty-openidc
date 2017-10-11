local url = require("socket.url")

local test_support = {}

-- must double percents for Lua regexes
function test_support.urlescape_for_regex(s)
  return url.escape(s):gsub("%%", "%%%%")
end




return test_support
