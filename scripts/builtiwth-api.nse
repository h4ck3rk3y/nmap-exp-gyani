local http = require "http"
local json = require "json"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"
local openssl = stdnse.silent_require "openssl"

-- Set your builtwith api key here, to avoid retyping.
local apikey = ""

author = "Gyanendra Mishra <anomaly.the@gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}

description = [[Queries BuiltWith API for the given targets and finds the technology stack
of the given domain.

N.B if you want this script to run completely passively make sure to
include the -sn -Pn -n flags.
]]

if not nmap.registry[SCRIPT_NAME] then
  nmap.registry[SCRIPT_NAME] = {
    apiKey = stdnse.get_script_args(SCRIPT_NAME .. ".apikey") or apiKey,
    count = 0
  }
end

local registry = nmap.registry[SCRIPT_NAME]
local arg_target = stdnse.get_script_args(SCRIPT_NAME .. ".target")


