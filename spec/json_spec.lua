local t = require("spec.support")
local json = require("loglens.json")
local lcg = require("tools.lcg")

local function decodes(text, expected)
  local value, err = json.decode(text)
  t.is_nil(err, "unexpected decode error for " .. text .. ": " .. tostring(err))
  t.eq(value, expected, "decoded value for " .. text)
end

local function rejects(text, fragment)
  local value, err = json.decode(text)
  t.is_nil(value, "should have rejected " .. t.inspect(text))
  t.ok(err, "an error message is required for " .. t.inspect(text))
  if fragment then
    t.contains(err, fragment)
  end
end

t.describe("json.decode accepts valid documents", function()
  t.it("decodes scalars", function()
    decodes("true", true)
    decodes("false", false)
    decodes("null", json.null)
    decodes('"abc"', "abc")
    decodes('""', "")
    decodes("  \t\r\n 7 \n", 7)
  end)

  t.it("decodes numbers with the right Lua subtype", function()
    t.eq(math.type(json.decode("0")), "integer")
    t.eq(math.type(json.decode("-12")), "integer")
    t.eq(math.type(json.decode("1.0")), "float")
    t.eq(math.type(json.decode("1e2")), "float")
    decodes("0", 0)
    decodes("-0", 0)
    decodes("-0.0", -0.0)
    decodes("1.5", 1.5)
    decodes("-2.5e-3", -0.0025)
    decodes("1E+3", 1000.0)
    decodes("0.1e1", 1.0)
    decodes("9223372036854775807", math.maxinteger)
    t.eq(math.type(json.decode("9223372036854775808")), "float")
    t.near(json.decode("123456789012345678901234567890"), 1.2345678901234568e29, 1e15)
  end)

  t.it("decodes containers", function()
    decodes("[]", {})
    decodes("{}", {})
    decodes("[1,2,3]", { 1, 2, 3 })
    decodes('{"a":1,"b":[true,null,"x"]}', { a = 1, b = { true, json.null, "x" } })
    decodes(' { "a" : [ 1 , 2 ] } ', { a = { 1, 2 } })
    decodes('[[[[1]]]]', { { { { 1 } } } })
    decodes('{"a":{"b":{"c":null}}}', { a = { b = { c = json.null } } })
  end)

  t.it("keeps the last duplicate key", function()
    decodes('{"a":1,"a":2}', { a = 2 })
  end)

  t.it("decodes every escape", function()
    decodes([["\"\\\/\b\f\n\r\t"]], '"\\/\b\f\n\r\t')
    decodes([["\u0041\u00e9\u20AC"]], "A\u{e9}\u{20ac}")
    decodes([["\u0000"]], "\0")
    decodes([["a\u0000b"]], "a\0b")
  end)

  t.it("combines surrogate pairs", function()
    decodes([["\uD83D\uDE00"]], "\u{1F600}")
    decodes([["\ud834\udd1e"]], "\u{1D11E}")
    decodes([["x\uD83D\uDE00y"]], "x\u{1F600}y")
  end)

  t.it("passes raw UTF-8 through", function()
    decodes('"caf\u{e9} \u{65e5}\u{672c}"', "caf\u{e9} \u{65e5}\u{672c}")
  end)

  t.it("tags empty objects so they survive a round trip", function()
    t.eq(json.encode(json.decode("{}")), "{}")
    t.eq(json.encode(json.decode("[]")), "[]")
    t.eq(json.encode(json.decode('{"a":{},"b":[]}')), '{"a":{},"b":[]}')
  end)

  t.it("accepts nesting at the depth limit", function()
    local ok = string.rep("[", 64) .. string.rep("]", 64)
    t.ok(json.decode(ok))
    local deep, err = json.decode(string.rep("[", 65) .. string.rep("]", 65))
    t.is_nil(deep)
    t.contains(err, "maximum nesting depth")
    t.ok(json.decode(string.rep("[", 10) .. string.rep("]", 10), { max_depth = 10 }))
    t.is_nil(json.decode(string.rep("[", 11) .. string.rep("]", 11), { max_depth = 10 }))
  end)

  t.it("survives absurd nesting without crashing", function()
    local value, err = json.decode(string.rep("[", 100000))
    t.is_nil(value)
    t.contains(err, "maximum nesting depth")
    local objs = json.decode(string.rep('{"a":', 100000))
    t.is_nil(objs)
  end)
end)

t.describe("json.decode rejects invalid documents", function()
  t.it("rejects structural errors", function()
    for _, text in ipairs({
      "",
      "   ",
      "[1,]",
      "[,1]",
      "[1 2]",
      "[1",
      "[",
      "]",
      "{",
      '{"a"}',
      '{"a":}',
      '{"a" 1}',
      '{"a":1,}',
      "{,}",
      "{a:1}",
      "{'a':1}",
      '{1:2}',
      '{"a":1 "b":2}',
      "[1]]",
      "[1]x",
      '{"a":1}}',
      "1 2",
      "nul",
      "tru",
      "truex",
      "[truex]",
      "True",
      "undefined",
      "[1]//c",
      "/*c*/[1]",
      "\239\187\191[1]",
    }) do
      rejects(text)
    end
  end)

  t.it("rejects invalid numbers", function()
    for _, text in ipairs({ "01", "-01", "00", "+1", ".5", "1.", "1.e3", "1e", "1e+", "-", "--1",
      "0x10", "1_000", "1,5", "- 1" }) do
      rejects(text)
    end
    rejects("[01]", "leading zeros")
    rejects("1e999", "out of range")
    rejects("-1e999", "out of range")
  end)

  t.it("rejects NaN and Infinity", function()
    rejects("NaN", "NaN and Infinity")
    rejects("[NaN]")
    rejects("Infinity", "NaN and Infinity")
    rejects("-Infinity", "Infinity")
    rejects("[-Infinity]")
    rejects('{"a":Infinity}')
  end)

  t.it("rejects bad strings", function()
    rejects('"abc', "unterminated")
    rejects('"abc\\', "unterminated")
    rejects('"\\x41"', "invalid escape")
    rejects('"\\u12"', "invalid \\u escape")
    rejects('"\\u12G4"', "invalid \\u escape")
    rejects('"\\U0041"', "invalid escape")
    rejects('"a\tb"', "control character")
    rejects('"a\nb"', "control character")
    rejects('"a\0b"', "control character")
    rejects("'abc'")
  end)

  t.it("rejects unpaired surrogates", function()
    rejects([["\uD800"]], "surrogate")
    rejects([["\uDC00"]], "surrogate")
    rejects([["\uD800\u0041"]], "surrogate")
    rejects([["\uD800x"]], "surrogate")
    rejects([["\uDC00\uD800"]], "surrogate")
  end)

  t.it("rejects invalid UTF-8 unless asked to replace it", function()
    rejects('"a\xffb"', "UTF-8")
    rejects('"\xc3"', "UTF-8")
    local value = json.decode('"a\xffb"', { utf8 = "replace" })
    t.eq(value, "a\u{FFFD}b")
    t.eq(json.decode('{"k\xff":"v\xfe"}', { utf8 = "replace" }), { ["k\u{FFFD}"] = "v\u{FFFD}" })
  end)

  t.it("reports the byte position", function()
    local _, err = json.decode('{"a":1,}')
    t.eq(err, "expected a string key at position 8")
    local _, err2 = json.decode("[1, 2, x]")
    t.eq(err2, "unexpected character at position 8")
    local _, err3 = json.decode("[1] x")
    t.eq(err3, "unexpected trailing characters at position 5")
  end)

  t.it("raises only for non-string input", function()
    t.raises(function()
      json.decode(nil)
    end, "expects a string")
    t.raises(function()
      json.decode(42)
    end, "expects a string")
  end)
end)

t.describe("json.encode", function()
  t.it("encodes scalars", function()
    t.eq(json.encode(true), "true")
    t.eq(json.encode(false), "false")
    t.eq(json.encode(json.null), "null")
    t.eq(json.encode(7), "7")
    t.eq(json.encode(-7), "-7")
    t.eq(json.encode(2.5), "2.5")
    t.eq(json.encode(3.0), "3")
    t.eq(json.encode(-0.0), "0")
    t.eq(json.encode(1e20), "1e+20")
    t.eq(json.encode(1 / 3), "0.3333333333333333")
    t.eq(json.encode(0.1), "0.1")
    t.eq(json.encode(math.maxinteger), "9223372036854775807")
    t.eq(json.encode("x"), '"x"')
  end)

  t.it("round-trips floats exactly", function()
    for _, x in ipairs({ 0.1, 1 / 3, 2 / 3, 123456.789, 1e-7, 5e-324, 1.7976931348623157e308, 0.30000000000000004 }) do
      t.eq(json.decode(json.encode(x)), x)
    end
  end)

  t.it("escapes strings", function()
    t.eq(json.encode('a"b\\c'), '"a\\"b\\\\c"')
    t.eq(json.encode("\n\r\t\b\f"), '"\\n\\r\\t\\b\\f"')
    t.eq(json.encode("\0\1\31"), '"\\u0000\\u0001\\u001f"')
    t.eq(json.encode("/"), '"/"')
    t.eq(json.encode("\u{e9}\u{1F600}"), '"\u{e9}\u{1F600}"')
    t.eq(json.encode("\127"), '"\\u007f"')
  end)

  t.it("repairs invalid UTF-8", function()
    t.eq(json.encode("a\xffb"), '"a\u{FFFD}b"')
    t.eq(json.encode({ ["k\xff"] = 1 }), '{"k\u{FFFD}":1}')
  end)

  t.it("escapes markup characters in html_safe mode", function()
    local out = json.encode({ x = "</script><!-- & \u{2028}\u{2029}" }, { html_safe = true })
    t.eq(out, '{"x":"\\u003c/script\\u003e\\u003c!-- \\u0026 \\u2028\\u2029"}')
    t.not_contains(out, "<")
    t.not_contains(out, ">")
    t.eq(json.decode(out).x, "</script><!-- & \u{2028}\u{2029}")
    t.eq(json.encode("<"), '"<"')
  end)

  t.it("distinguishes arrays and objects", function()
    t.eq(json.encode({}), "[]")
    t.eq(json.encode(json.object()), "{}")
    t.eq(json.encode(json.array()), "[]")
    t.eq(json.encode({ 1, 2, 3 }), "[1,2,3]")
    t.eq(json.encode({ a = 1 }), '{"a":1}')
    t.eq(json.encode({ { a = 1 }, { b = {} } }), '[{"a":1},{"b":[]}]')
    t.eq(json.encode({ 1, json.null, 3 }), "[1,null,3]")
  end)

  t.it("sorts keys deterministically and honours key_order", function()
    t.eq(json.encode({ b = 1, a = 2, c = 3 }), '{"a":2,"b":1,"c":3}')
    t.eq(json.encode({ b = 1, a = 2, c = 3, schema = 0 }, { key_order = { "schema", "c" } }),
      '{"schema":0,"c":3,"a":2,"b":1}')
  end)

  t.it("rejects values it cannot represent and names the path", function()
    t.eq(t.raises(function()
      json.encode({ a = { b = { 1, print } } })
    end, "type 'function'"), "json.encode: cannot encode a value of type 'function' at $.a.b[2]")
    t.raises(function()
      json.encode(0 / 0)
    end, "NaN")
    t.raises(function()
      json.encode(math.huge)
    end, "Infinity")
    t.raises(function()
      json.encode({ [1] = "a", [3] = "c" })
    end, "keys must be strings")
    t.raises(function()
      json.encode({ 1, 2, x = 3 })
    end, "keys must be strings")
    t.raises(function()
      json.encode({ [true] = 1 })
    end, "keys must be strings")
    t.raises(function()
      json.encode(coroutine.create(print))
    end, "type 'thread'")
  end)

  t.it("detects cycles through the depth limit", function()
    local cyclic = {}
    cyclic.self = cyclic
    t.raises(function()
      json.encode(cyclic)
    end, "maximum nesting depth")
  end)

  t.it("pretty-prints with scalar arrays on one line", function()
    local out = json.encode({ name = "x", list = { 1, 2, 3 }, nested = { { a = 1 } }, empty = {} },
      { indent = 2 })
    t.eq(out, table.concat({
      "{",
      '  "empty": [],',
      '  "list": [1, 2, 3],',
      '  "name": "x",',
      '  "nested": [',
      "    {",
      '      "a": 1',
      "    }",
      "  ]",
      "}",
    }, "\n"))
  end)

  t.it("wraps long scalar arrays", function()
    local values = {}
    for i = 1, 60 do
      values[i] = i * 1000
    end
    local out = json.encode({ v = values }, { indent = 2, wrap = 60 })
    for _, line in ipairs(t.lines_of(out)) do
      t.lt(#line, 61)
    end
    t.eq(json.decode(out).v, values)
  end)
end)

t.describe("json round trips and fuzzing", function()
  local function random_value(rng, depth)
    local roll = rng:range(1, depth > 3 and 6 or 9)
    if roll == 1 then
      return rng:range(-1000000, 1000000)
    elseif roll == 2 then
      return rng:float() * 2000 - 1000
    elseif roll == 3 then
      return rng:chance(0.5)
    elseif roll == 4 then
      return json.null
    elseif roll <= 6 then
      local bytes = {}
      for i = 1, rng:range(0, 12) do
        bytes[i] = rng:pick({ "a", "Z", " ", '"', "\\", "\n", "\u{e9}", "\u{1F600}", "<", "/", "\1" })
      end
      return table.concat(bytes)
    elseif roll <= 8 then
      local list = {}
      for i = 1, rng:range(0, 4) do
        list[i] = random_value(rng, depth + 1)
      end
      return list
    end
    local object = {}
    for _ = 1, rng:range(0, 4) do
      object["k" .. rng:range(1, 50)] = random_value(rng, depth + 1)
    end
    return object
  end

  t.it("decode(encode(x)) == x for random documents (compact and pretty)", function()
    local rng = lcg.new(20260101)
    for _ = 1, 300 do
      local value = random_value(rng, 0)
      t.eq(json.decode(json.encode(value)), value)
      t.eq(json.decode(json.encode(value, { indent = 2 })), value)
      t.eq(json.decode(json.encode(value, { html_safe = true })), value)
    end
  end)

  t.it("encoding is deterministic", function()
    local rng = lcg.new(5)
    for _ = 1, 50 do
      local value = random_value(rng, 0)
      t.eq(json.encode(value), json.encode(value))
    end
  end)

  t.it("never raises on mutated or random input", function()
    local rng = lcg.new(99)
    local seeds = {
      '{"a":[1,2.5e3,"x\\u00e9\\ud83d\\ude00"],"b":{"c":null,"d":true}}',
      '["\\n",-0,0.5,{"":[]}]',
      '{"request":{"headers":{"User-Agent":["curl/8"]}},"status":200}',
    }
    for _ = 1, 3000 do
      local text = rng:pick(seeds)
      local chars = {}
      for i = 1, #text do
        chars[i] = text:sub(i, i)
      end
      for _ = 1, rng:range(1, 4) do
        local at = rng:range(1, #chars)
        local op = rng:range(1, 3)
        if op == 1 then
          table.remove(chars, at)
        elseif op == 2 then
          chars[at] = string.char(rng:range(0, 255))
        else
          table.insert(chars, at, rng:pick({ "[", "]", "{", "}", ",", ":", '"', "\\", "-", "e" }))
        end
        if #chars == 0 then
          chars[1] = "x"
        end
      end
      local ok, value, err = pcall(json.decode, table.concat(chars))
      t.ok(ok, "decode must not raise")
      t.ok(value ~= nil or err ~= nil)
    end
  end)

  t.it("decodes a large document quickly", function()
    local parts = {}
    for i = 1, 5000 do
      parts[i] = string.format('{"id":%d,"name":"item-%d","tags":["a","b","c"],"v":%d.5}', i, i, i)
    end
    local text = "[" .. table.concat(parts, ",") .. "]"
    local started = os.clock()
    local value = json.decode(text)
    t.eq(#value, 5000)
    t.eq(value[5000].name, "item-5000")
    t.lt(os.clock() - started, 3)
  end)
end)
