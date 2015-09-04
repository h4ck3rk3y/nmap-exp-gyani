local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
  This script tries to detect cctv dvr web interfaces.
]]

---
-- @usage nmap --script http-cctv-interface
--
-- @args http-cctv-interface.url The url relative to the host to access.
--
-- @output
-- | http-cctv-interface:
-- |_  DVR IE ActiveX HTTP interface Version: webdvr2.13.1.9_0.0.0.0.cab v2,13,1,9
--
-- @xmloutput
-- <elem key="DVR IE ActiveX HTTP interface Version">webdvr2.13.1.9_0.0.0.0.cab v2,13,1,9</elem>

author = "Gyanendra Mishra"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "default", "discovery"}


portrule = shortport.http

action = function(host, port)
  local url = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local response = http.get(host, port, url)
  local output = stdnse.output_table()
  if response.body:lower():match("dvr web%s?viewer") then
    local v1, v2, v3 = response.body:match('[cC][oO][dD][eE][bB][aA][sS][eE]="(.-)%.(%w%w%w).version=(%d%d?%d?,%d%d?%d?,%d%d?%d?,%d%d?%d?)"')
    local version = string.format("%s.%s v%s", v1, v2, v3)
    if not version then return end
    output["DVR IE ActiveX HTTP interface Version"] = version
    return output
  end
end