local adcc = {}

-- Secure environment setup
local function qwzxp()
    local env = {}
    local mt = {
        __index = function(t, k) return nil end,
        __newindex = function(t, k, v)
            if k == "loadstring" or k == "_G" then return end
            rawset(t, k, v)
        end,
        __metatable = false
    }
    setmetatable(env, mt)
    return env
end

-- Safe loadstring wrapper
local jklmn = (getfenv and getfenv(0) or _G).loadstring
if type(jklmn) ~= "function" then
    jklmn = nil
else
    local bcdfg, err = jklmn("return true")
    if not bcdfg or err or not bcdfg() then
        jklmn = nil
    end
end

local function vbnmg()
    if not jklmn then
        return function() return function() end end
    end
    return function(code)
        local chunk, err = jklmn(code)
        if not chunk or err then
            return function() end
        end
        local env = qwzxp()
        setfenv(chunk, env)
        return chunk
    end
end

-- Hex decoding
local function zxcvb(hex)
    if type(hex) ~= "string" or #hex % 2 ~= 0 or not hex:match("^[0-9a-fA-F]+$") then
        return ""
    end
    local str = {}
    for i = 1, #hex, 2 do
        local byte = tonumber(hex:sub(i, i+1), 16)
        if not byte then return "" end
        str[#str+1] = string.char(byte)
    end
    return table.concat(str)
end

-- Key derivation
local function lkjhg()
    local seed = tostring({}) .. tostring(os.time()) .. tostring(math.random(1, 1000000))
    local key = 0
    for i = 1, #seed do
        key = bit32.bxor(key, string.byte(seed, i) or 0)
        key = (key * 31 + i * 997) % 0xFFFFFFFF
    end
    return key
end

-- Signature computation
local function poiuy(data, key)
    local hash = tonumber(key) or 42
    for i = 1, #data do
        hash = bit32.bxor(hash, string.byte(data, i) or 0)
        hash = (hash * 31 + i * 997) % 0xFFFFFFFF
    end
    return string.format("%08x", hash)
end

-- Decryption
local function mnbvc(hexEncrypted, key)
    if type(hexEncrypted) ~= "string" or #hexEncrypted < 8 then
        return ""
    end

    local signature = hexEncrypted:sub(-8)
    local mainData = hexEncrypted:sub(1, -9)
    local expectedSig = poiuy(mainData, key)
    if signature ~= expectedSig then
        return ""
    end

    local binaryData = zxcvb(mainData)
    if #binaryData == 0 then
        return ""
    end

    local function trews(key, length)
        local expanded = {}
        local keyStr = tostring(key)
        local hash = 0
        for i = 1, length do
            local char = string.byte(keyStr, (i % #keyStr) + 1) or 0
            hash = (hash * 31 + char + i * 997) % 256
            local pos = (i * char + hash) % #keyStr + 1
            local val = string.byte(keyStr, pos) or 0
            local mixed = bit32.bxor(val, hash, i % 256)
            expanded[i] = (mixed + i * 7) % 256
        end
        return expanded
    end

    local keySchedule = trews(key, #binaryData * 3)
    local plaintext = {}
    local keyIndex = 1

    -- Reverse third pass
    for i = 1, #binaryData do
        local byte = string.byte(binaryData, i)
        local original = (byte - i * 3 - keySchedule[#binaryData + i]) % 256
        plaintext[i] = string.char(original)
    end

    -- Reverse second pass
    local feedback = 0
    for i = 1, #plaintext do
        local byte = string.byte(plaintext[i])
        local derotated = bit32.bxor(byte, feedback)
        feedback = (feedback + derotated) % 256
        plaintext[i] = string.char(derotated)
    end

    -- Reverse first pass
    for i = 1, #plaintext do
        local byte = string.byte(plaintext[i])
        local decrypted = bit32.bxor(byte, keySchedule[keyIndex])
        plaintext[i] = string.char(decrypted)
        keyIndex = keyIndex + 1
    end

    return table.concat(plaintext)
end

-- Main entry point
function adcc.l(encrypted_code)
    local scy = pcall(function()
        local chunk = jklmn([[return tostring({}):match("table: 0x[0-9a-f]+")]])
        if not chunk then return false end
        local env = qwzxp()
        setfenv(chunk, env)
        return chunk() ~= nil
    end)

    if not scy then
        return
    end

    local key = lkjhg()
    local dcc = mnbvc(encrypted_code, key)
    if dcc == "" then
        return
    end

    local loader = vbnmg()
    local chunk = loader(dcc)
    local env = qwzxp()
    setfenv(chunk, env)
    pcall(chunk)
end


return adcc
