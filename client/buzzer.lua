local moduleName = ...
local M = {}
_G[moduleName] = M

function M.unlock(secret)
    local secret_hash = crypto.sha1(secret)
    local conn = net.createConnection(net.UDP, 0)
    conn:connect(4242, "192.168.12.152")
    conn:on("receive", function (sck, data)
        if #data == 30 and string.byte(data, 1) == 2 and string.byte(data, 2) == 1 then
            -- received apparently valid response
            local time = string.sub(data, 3, 6)
            local seq = string.sub(data, 7, 10)
            local challenge = string.sub(data, 11, 30)
            local challenge_hash = crypto.hmac("SHA1", challenge, secret)
            local response = string.char(3) .. string.char(1) .. secret_hash .. time .. seq .. challenge_hash
            conn:send(response)
        end
    end)

    conn:send(string.char(1) .. string.char(1) .. secret_hash)
end

return M
