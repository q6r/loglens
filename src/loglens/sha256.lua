--- SHA-256 and Base64 in plain Lua 5.3+ (integer bit operators), used to pin the inline scripts and
-- styles of the HTML report in its Content-Security-Policy.
-- @module loglens.sha256
local M = {}

local pack, unpack = string.pack, string.unpack
local concat = table.concat
local MASK = 0xffffffff

local K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function rotate_right(x, n)
  return ((x >> n) | (x << (32 - n))) & MASK
end

--- SHA-256 digest.
-- @param message string
-- @return string 32 raw bytes
function M.digest(message)
  local length = #message
  message = message .. "\128" .. string.rep("\0", (55 - length) % 64) .. pack(">I8", length * 8)
  local h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
  local h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  local w = {}
  for block = 1, #message, 64 do
    for i = 1, 16 do
      w[i] = unpack(">I4", message, block + (i - 1) * 4)
    end
    for i = 17, 64 do
      local a, b = w[i - 15], w[i - 2]
      local s0 = rotate_right(a, 7) ~ rotate_right(a, 18) ~ (a >> 3)
      local s1 = rotate_right(b, 17) ~ rotate_right(b, 19) ~ (b >> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK
    end
    local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
    for i = 1, 64 do
      local s1 = rotate_right(e, 6) ~ rotate_right(e, 11) ~ rotate_right(e, 25)
      local choice = (e & f) ~ (~e & g)
      local t1 = (h + s1 + choice + K[i] + w[i]) & MASK
      local s0 = rotate_right(a, 2) ~ rotate_right(a, 13) ~ rotate_right(a, 22)
      local majority = (a & b) ~ (a & c) ~ (b & c)
      local t2 = (s0 + majority) & MASK
      h, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASK, c, b, a, (t1 + t2) & MASK
    end
    h0, h1, h2, h3 = (h0 + a) & MASK, (h1 + b) & MASK, (h2 + c) & MASK, (h3 + d) & MASK
    h4, h5, h6, h7 = (h4 + e) & MASK, (h5 + f) & MASK, (h6 + g) & MASK, (h7 + h) & MASK
  end
  return pack(">I4I4I4I4I4I4I4I4", h0, h1, h2, h3, h4, h5, h6, h7)
end

--- SHA-256 digest as lower-case hexadecimal.
-- @param message string
-- @return string 64 characters
function M.hex(message)
  return (M.digest(message):gsub(".", function(byte)
    return string.format("%02x", byte:byte())
  end))
end

local ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

--- Standard Base64 (with padding).
-- @param data string
-- @return string
function M.base64(data)
  local out = {}
  for i = 1, #data, 3 do
    local a, b, c = data:byte(i, i + 2)
    local n = (a << 16) | ((b or 0) << 8) | (c or 0)
    local c1, c2, c3, c4 = (n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63
    out[#out + 1] = ALPHABET:sub(c1 + 1, c1 + 1) .. ALPHABET:sub(c2 + 1, c2 + 1)
      .. (b and ALPHABET:sub(c3 + 1, c3 + 1) or "=") .. (c and ALPHABET:sub(c4 + 1, c4 + 1) or "=")
  end
  return concat(out)
end

--- A Content-Security-Policy hash source for inline code: `'sha256-<base64 digest>'`.
-- @param text string the exact content of the `<script>` or `<style>` element
-- @return string
function M.csp_source(text)
  return "'sha256-" .. M.base64(M.digest(text)) .. "'"
end

return M
