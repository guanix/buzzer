local buzzer = require("buzzer")
local socket = require("socket")

buzzer.setup("soopersekret", {"guanrocks"})

local udp = socket.udp()
udp:setsockname("*", 4242)
udp:settimeout(nil)

print("listening")

while true do
    local data, ip, port = udp:receivefrom()
    print("received from " .. ip .. ":" .. port)

    buzzer.handlePacket(data, function (response)
        udp:sendto(response, ip, port)
    end, function ()
        print("we are supposed to unlock now")
    end)
    socket.sleep(0.01)
end
