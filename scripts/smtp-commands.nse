local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to use EHLO and HELP to gather the Extended commands supported by an
SMTP server.
]]

---
-- @usage
-- nmap --script smtp-commands.nse [--script-args smtp-commands.domain=<domain>] -pT:25,465,587 <host>
--
-- @output
-- PORT   STATE SERVICE REASON  VERSION
-- 25/tcp open  smtp    syn-ack Microsoft ESMTP 6.0.3790.3959
-- | smtp-commands:
-- |   EHLO Returned: SIZE 52428800 8BITMIME AUTH PLAIN LOGIN STARTTLS HELP
-- |_  HELP Returned: AUTH STARTTLS HELO EHLO MAIL RCPT DATA NOOP QUIT RSET HELP
--
-- @args smtp.domain or smtp-commands.domain Define the domain to be used in the SMTP commands.
--
-- @xmloutput
-- <table key="EHLO Returned">
--   <elem>SIZE 52428800</elem>
--   <elem>8BITMIME</elem>
--   <elem>AUTH PLAIN LOGIN</elem>
--   <elem>STARTTLS</elem>
--   <elem>HELP</elem>
-- </table>
-- <table key="HELP Returned">
--   <elem>AUTH</elem>
--   <elem>STARTTLS</elem>
--   <elem>HELO</elem>
--   <elem>EHLO</elem>
--   <elem>MAIL</elem>
--   <elem>RCPT</elem>
--   <elem>DATA</elem>
--   <elem>NOOP</elem>
--   <elem>QUIT</elem>
--   <elem>RSET</elem>
--   <elem>HELP</elem>
-- </table>
--
-- changelog
-- 1.1.0.0 - 2007-10-12
-- + added HELP command in addition to EHLO
-- 1.2.0.0 - 2008-05-19
-- + made output single line, comma-delimited,   instead of
--   CR LF delimited on multi-lines
-- + was able to use regular text and not hex codes
-- 1.3.0.0 - 2008-05-21
-- + more robust handling of problems
-- + uses verbosity and debugging to decide if you need to
--   see certain errors and if the output is in a line or
--   in , for lack of a better word, fancy format
-- + I am not able to do much testing because my new ISP blocks
--   traffic going to port 25 other than to their mail servers as
--   a "security" measure.
-- 1.3.1.0 - 2008-05-22
-- + minor tweaks to get it working when one of the requests fails
--   but not both of them.
-- 1.5.0.0 - 2008-08-15
-- + updated to use the nsedoc documentation system
-- 1.6.0.0 - 2008-10-06
-- + Updated gsubs to handle different formats, pulls out extra spaces
--   and normalizes line endings
-- 1.7.0.0 - 2008-11-10
-- + Better normalization of output, remove "250 " from EHLO output,
--   don't comma-separate HELP output.
-- 2.0.0.0 - 2010-04-19
-- + Complete rewrite based off of Arturo 'Buanzo' Busleiman's SMTP open
--   relay detector script.
-- 2.0.1.0 - 2010-04-27
-- + Incorporated advice from Duarte Silva (http://seclists.org/nmap-dev/2010/q2/277)
--   - 'domain' can be specified via a script-arg
--   - removed extra EHLO command that was redundant and not needed
--   - fixed two quit()s to include a return value
-- + To reiterate, this is a blatant cut and paste job of Arturo 'Buanzo'
--   Busleiman's SMTP open relay detector script and Duarte Silva's SMTP
--   user enumeration script.
--   Props to them for doing what they do and letting me ride on their coattails.
-- 2.1.0.0 - 2011-06-01
-- + Rewrite the script to use the smtp.lua library.
-- 3.0.0.0 - 2015-08-09
-- + Replaced the multiple gsub calls with single gsubs overloaded with function as replace argument.
-- + Added XML output.

author = {"Jason DePriest", "Gyanendra Mishra"}
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule = shortport.port_or_service({ 25, 465, 587 },
  { "smtp", "smtps", "submission" })

local state = {
  lc = 0,
  result = stdnse.output_table()
}

local function parse_ehlo(line)
  if state.lc ~= 0 and #line > 0 and line:match("[%u%d%s]*") == line then
    state.result["EHLO Returned"] = state.result["EHLO Returned"] or {}
    table.insert(state.result["EHLO Returned"], line)
  end
  state.lc = state.lc + 1
end

local function parse_help(line)
  if state.lc ~= 0 then
    local commands = stdnse.strsplit("%s",line)
    state.result["HELP Returned"] = state.result["HELP Returned"] or {}
    for _, command in pairs(commands) do
      if #command > 0 and command:match("[%u%d]*") == command then
        state.result["HELP Returned"][command] = true
      end
    end
  end
  state.lc = state.lc + 1
end

local function go(host, port)
  local options = {
    timeout = 10000,
    recv_before = true,
    ssl = true,
  }
  local spacesep = {
  __tostring = function (t)
    return table.concat(t, " ")
  end
  }
  local domain, hostname = stdnse.get_script_args(SCRIPT_NAME .. ".domain") or
  smtp.get_domain(host)

  local result,commands, status = stdnse.output_table()
  -- Try to connect to server.
  local socket, response = smtp.connect(host, port, options)
  if not socket then
    return false, string.format("Couldn't establish connection on port %i", port.number)
  end

  status, response = smtp.ehlo(socket, domain)
  if not status then
    return status, response
  end
  string.gsub(response, "250[-%s](.-)%s?[\n\r]", parse_ehlo)
  setmetatable(state.result["EHLO Returned"], spacesep)
  status, response = smtp.help(socket)
  if status then
    state.lc = 0
    string.gsub(response, "214[-%s2%.%0]+(.-)%s?[\n\r]", parse_help)
    if state.result["HELP Returned"] then
      state.result["HELP Returned"] = stdnse.keys(state.result["HELP Returned"])
      setmetatable(state.result["HELP Returned"], spacesep)
    end
    smtp.quit(socket)
  end
  return true, state.result
end

action = function(host, port)
  local status, result = go(host, port)
  if status then
    return result
  end
end
