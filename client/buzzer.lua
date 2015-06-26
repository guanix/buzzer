local moduleName = ...
local M = {}
_G[moduleName] = M

local conn
local secret_hash

function M.setup(secret, ip, port, callback)
    secret_hash = crypto.sha1(secret)

    conn = net.createConnection(net.UDP, 0)
    conn:connect(port, ip)

    conn:on("receive", function (sck, data)
        if #data == 30 and string.byte(data, 1) == 2 and string.byte(data, 2) == 1 then
            -- received apparently valid response
            local time = string.sub(data, 3, 6)
            local seq = string.sub(data, 7, 10)
            local challenge = string.sub(data, 11, 30)
            local challenge_hash = crypto.hmac("SHA1", challenge, secret)
            local response = string.char(3) .. string.char(1) .. secret_hash .. time .. seq .. challenge_hash
            conn:send(response)
        elseif #data == 30 and string.byte(data, 1) == 4 and string.byte(data, 2) == 1 and callback then
            -- this is a confirmation, we only verify it if there's a callback
            local text = string.sub(data, 3, 10) .. string.char(1)
            local code = crypto.hmac("SHA1", text, secret)
            if code == string.sub(data, 11, 30) then
                callback(true)
            else
                callback(false)
            end
        end
    end)
end

function M.unlock()
    -- simply send the hashed version of our secret, already computed
    -- the rest is handled in the callback created in setup
    conn:send(string.char(1) .. string.char(1) .. secret_hash)
end

return M
