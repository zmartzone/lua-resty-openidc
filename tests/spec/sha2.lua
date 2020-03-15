-- Copy of https://github.com/catwell/cw-lua/blob/master/sha256/sha256.lua

--- SHA-256 implementation by Pierre 'catwell' Chapuis
--- MIT licensed (see LICENSE.txt)
--- Only works on little endian platforms.

local ffi = require "ffi"
assert(ffi.abi("le"))

local bit = require "bit"
local band, bxor, bnot = bit.band, bit.bxor, bit.bnot
local rshift, rrot = bit.rshift, bit.ror

local ui32_8 = ffi.typeof("uint32_t[8]")
local uchar_32 = ffi.typeof("unsigned char[32]")
local uchar_256 = ffi.typeof("unsigned char[256]")
local uchar_vla = ffi.typeof("unsigned char[?]")

local H = ui32_8(
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
)

local K = ffi.new("uint32_t[64]",
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
)

local tohex = function(buf, n)
  local x = ffi.cast("unsigned char*", buf)
  local t = {}
  for i=0,n-1 do t[i+1] = string.format("%02x", x[i]) end
  return table.concat(t)
end

local write_i64 = function(buf, n)
  local q, r = math.floor(n/2^32), n%(2^32)
  local j = 0
  for i=24,0,-8 do
    buf[j] = band(rshift(q, i), 0xff)
    j = j + 1
  end
  for i=24,0,-8 do
    buf[j] = band(rshift(r, i), 0xff)
    j = j + 1
  end
end

local pad = function(msg) -- lua string -> buffer
  local l0 = #msg
  local n0 = ((56 - (l0 + 1)) % 64)
  local l1 = l0 + 1 + n0 + 8
  assert(l1%64 == 0, l1)
  local nchunks = l1/64
  local r = uchar_vla(l1)
  ffi.copy(r, msg, l0)
  r[l0] = 0x80
  write_i64(r+l1-8, 8*l0)
  return r, nchunks
end

local rcopy_32 = function(to, from, n) -- copy n 4B chunks, reversing them
  local x = ffi.cast("unsigned char*", to)
  local y = ffi.cast("unsigned char*", from)
  for i=0,n-1 do
    for j=0,3 do
      x[4*i+j] = y[4*i+3-j]
    end
  end
end

local transform = function(chunk, res) -- works on a 64B chunk
  local a, b, c, d = res[0], res[1], res[2], res[3]
  local e, f, g, h = res[4], res[5], res[6], res[7]
  local buf = uchar_256()
  rcopy_32(buf, chunk,16)
  local w = ffi.cast("uint32_t *", buf)
  local t1, t2, s0, s1
  for i=16,64-1 do
    t1, t2 = w[i-15], w[i-2]
    s0 = bxor( rrot(t1, 07), rrot(t1, 18), rshift(t1, 03) )
    s1 = bxor( rrot(t2, 17), rrot(t2, 19), rshift(t2, 10) )
    w[i] = w[i-16] + w[i-7] + s0 + s1 + 0LL -- 32 bit LuaJIT, see issue 1
  end
  for i=0,64-1 do
    s0 = bxor( rrot(a, 02), rrot(a, 13), rrot(a, 22) )
    s1 = bxor( rrot(e, 06), rrot(e, 11), rrot(e, 25) )
    t1 = s1 + h + w[i] + K[i] + bxor( band(e, f), band(bnot(e), g) )
    t2 = s0 + bxor( band(a ,b), band(a, c), band(b, c) )
    a, b, c, d, e, f, g, h = t1+t2, a, b, c, d+t1, e, f, g
  end
  res[0], res[1], res[2], res[3] = res[0]+a, res[1]+b, res[2]+c, res[3]+d
  res[4], res[5], res[6], res[7] = res[4]+e, res[5]+f, res[6]+g, res[7]+h
end

local sha256_calc = function(input)
  local chunks, nchunks = pad(input)
  local buf = ui32_8()
  ffi.copy(buf, H, ffi.sizeof(ui32_8))
  for i=0,nchunks-1 do transform(chunks+64*i, buf) end
  local res = uchar_32()
  rcopy_32(res, buf, 8)
  return res
end

local sha256_bytes = function(input)
  local r = sha256_calc(input)
  return ffi.string(r, 32)
end

local sha256_hex = function(input)
  local r = sha256_calc(input)
  return tohex(r, 32)
end

return {
  bytes = sha256_bytes,
  hex = sha256_hex,
}
