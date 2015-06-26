-- Door opening Lua server

local moduleName = ...
local M = {}
_G[moduleName] = M

-- We should switch this to CoAP once Guan writes a CoAP stack for Lua

-- 1. client-to-server: request challenge
--		byte 1:     1
--      byte 2:     1 (for unlock)
--      bytes 3-22: (binary) hash of the SHARED secret
-- 2. server-to-client: respond with challenge
--      byte 1:     2
--      byte 2:     1 (for unlock)
--      bytes 3-6:  timestamp (unix time_t)
--      bytes 7-10:  sequence number
--      bytes 11-30: challenge
--      the challenge is the HMAC of the SERVER secret and:
--          4-byte timestamp (network byte order)
--          4-byte sequence number (network byte order)
--          1-byte command 1 (for unlock)
--      (this is a stateless protocol)
-- 3. client-to-server: respond to challenge
--      byte 1:     3
--      byte 2:     1 (for unlock)
--      bytes 3-22: (binary) hash of the SHARED secret
--      bytes 23-26:  timestamp (unix time_t)
--      bytes 27-30:  sequence number
--      bytes 31-50: hmac of challenge with SHARED secret
-- 4. server-to-client: op successful
--      byte 1:     4
--      byte 2:     1
--      byte 3-6:   timestamp
--      byte 7-10:  sequence number
--      bytes 11-30: hmac with SHARED secret of:
--          4-byte timestamp
--          4-byte sequence number
--          1-byte command

local sha1 = require("sha1")
local struct = require("struct")

local secret
local shared_secrets
local shared_secrets_hashed = {}

local seq = 0

function M.setup(secret_arg, shared_secrets_arg)
    secret = secret_arg
    shared_secrets = shared_secrets_arg

    -- precompute hashed versions of the shared secrets
    for i, shared_secret in ipairs(shared_secrets) do
        local secret_hash = sha1.binary(shared_secret)
        shared_secrets_hashed[secret_hash] = shared_secret
    end
end

local function computeChallenge(time, seq, cmd)
    local text = struct.pack(">i4>i4B", time, seq, cmd)
    return sha1.hmac_binary(secret, text)
end

local function computeSignedResponse(client_secret, time, seq, cmd)
    local text = struct.pack(">i4>i4B", time, seq, cmd)
    return sha1.hmac_binary(client_secret, text)
end

function M.handlePacket(data, respond, action)
    if #data >= 22 then -- received packets are always at least 22 bytes
        local op = string.byte(data, 1)

        if op == 1 and #data == 22 then -- request challenge
            print("request challenge")

            local cmd = string.byte(data, 2)

            if cmd == 1 then
                local secret_hash = string.sub(data, 3, 22)
                local client_secret = shared_secrets_hashed[secret_hash]

                if client_secret then
                    print("found the secret")

                    -- calculate challenge
                    local time = os.time()
                    seq = seq + 1       -- increment the sequence number
                    local challenge = computeChallenge(time, seq, cmd)
                    local response = string.char(2) .. string.char(cmd) .. struct.pack(">i4", time) .. struct.pack(">i4", seq) .. challenge
                    respond(response)
                else
                    print("no match for the secret")
                end
            end
        elseif op == 3 and #data == 50 then -- received challenge response
            print("received challenge response")

            local cmd = string.byte(data, 2)

            if cmd == 1 then
                local secret_hash = string.sub(data, 3, 22)
                local client_secret = shared_secrets_hashed[secret_hash]

                if client_secret then
                    print("found the secret")

                    local localtime = os.time()
                    local time = struct.unpack(">i4", string.sub(data, 23, 26))
                    if localtime - time < 60 then -- can't be more than a minute old
                        -- verify the challenge signature
                        local seq = struct.unpack(">i4", string.sub(data, 27, 30))
                        local challenge = computeChallenge(time, seq, cmd)
                        local challenge_hash = sha1.hmac_binary(client_secret, challenge)
                        if challenge_hash == string.sub(data, 31, 50) then
                            print("challenge response correct!")
                            local response = string.char(4) .. string.char(cmd) .. struct.pack(">i4>i4", time, seq) .. computeSignedResponse(client_secret, time, seq, cmd)
                            respond(response)
                            action()
                        else
                            print("challlenge response wrong")
                        end
                    else
                        print("too old")
                    end
                end
            end
        end
    end
end

return M
