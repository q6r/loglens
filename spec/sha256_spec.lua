local t = require("spec.support")
local sha256 = require("loglens.sha256")

t.describe("sha256", function()
  t.it("matches the FIPS 180-4 test vectors", function()
    t.eq(sha256.hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    t.eq(sha256.hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    t.eq(sha256.hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    t.eq(sha256.hex("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
      "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
  end)

  t.it("handles every padding length around the block size", function()
    -- reference digests computed with Node's crypto module for strings of 0..130 repeated 'a'
    local known = {
      [55] = "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
      [56] = "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
      [63] = "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
      [64] = "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
      [65] = "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
    }
    for length, digest in pairs(known) do
      t.eq(sha256.hex(string.rep("a", length)), digest, length .. " bytes")
    end
  end)

  t.it("returns 32 raw bytes and handles binary data", function()
    local raw = sha256.digest("\0\255\0\255")
    t.eq(#raw, 32)
    t.neq(raw, sha256.digest("\0\255\0\254"))
    t.eq(#sha256.digest(string.rep("\255", 100000)), 32)
  end)
end)

t.describe("sha256.base64", function()
  t.it("matches the RFC 4648 vectors", function()
    t.eq(sha256.base64(""), "")
    t.eq(sha256.base64("f"), "Zg==")
    t.eq(sha256.base64("fo"), "Zm8=")
    t.eq(sha256.base64("foo"), "Zm9v")
    t.eq(sha256.base64("foob"), "Zm9vYg==")
    t.eq(sha256.base64("fooba"), "Zm9vYmE=")
    t.eq(sha256.base64("foobar"), "Zm9vYmFy")
    t.eq(sha256.base64("\255\254\253"), "//79")
  end)

  t.it("builds Content-Security-Policy hash sources", function()
    t.eq(sha256.csp_source("abc"), "'sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0='")
  end)
end)
