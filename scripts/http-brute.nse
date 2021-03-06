local brute = require "brute"
local creds = require "creds"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local stdnse = require "stdnse"

description = [[
Performs brute force password auditing against http basic, digest and ntlm authentication.
]]

---
-- @usage
-- nmap --script http-brute -p 80 <host>
--
-- This script uses the unpwdb and brute libraries to perform password
-- guessing. Any successful guesses are stored in the nmap registry, using
-- the creds library, for other scripts to use.
--
-- @output
-- PORT     STATE SERVICE REASON
-- 80/tcp   open  http    syn-ack
-- | http-brute: 
-- |   Accounts: 
-- |     user:user - Valid credentials
-- |_  Statistics: Performed 123 guesses in 1 seconds, average tps: 123
--
--
-- Summary
-- -------
--   x The Driver class contains the driver implementation used by the brute
--     library
--
-- @args http-brute.path points to the path protected by authentication (default: <code>/</code>)
-- @args http-brute.hostname sets the host header in case of virtual hosting
-- @args http-brute.method sets the HTTP method to use (default: <code>GET</code>)

--
-- Version 0.1
-- Created 07/30/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Version 0.2
-- 07/26/2012 - v0.2 - added digest auth support (Piotr Olma)
-- Version 0.3
-- Created 06/20/2015 - added ntlm auth support (Gyanendra Mishra)
--
-- @xmloutput
-- <table key="Accounts">
--   <table>
--     <elem key="state">Valid credentials</elem>
--     <elem key="username">user</elem>
--     <elem key="password">user</elem>
--   </table>
-- </table>
-- <elem key="Statistics">Performed 123 guesses in 1 seconds, average
-- tps: 123</elem>


author = {"Patrik Karlsson", "Piotr Olma", "Gyanendra Mishra"}
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

Driver = {

  new = function(self, host, port, opts)
    local o = {port=port, path=opts.path, method=opts.method, digestauth=opts.digestauth, ntlmauth=opts.ntlmauth}
    setmetatable(o, self)
    self.__index = self
    o.host = stdnse.get_script_args("http-brute.hostname") or host
    return o
  end,

  connect = function( self )
    -- This will cause problems, as there is no way for us to "reserve"
    -- a socket. We may end up here early with a set of credentials
    -- which won't be guessed until the end, due to socket exhaustion.
    return true
  end,

  login = function( self, username, password )
    local response
    local opts_table
    if self.digestauth then
      -- we need to supply the no_cache directive, or else the http library
      -- incorrectly tells us that the authentication was successful
      opts_table = { auth = { username = username, password = password, digest = true }, no_cache = true }
    elseif self.ntlmauth then
      opts_table = { auth = { username = username, password = password, ntlm = true }, no_cache = true }
    else
      opts_table = { auth = { username = username, password = password }, no_cache = true }
    end
    response = http.generic_request( self.host, self.port, self.method, self.path, opts_table)

    if not response.status then
      local err = brute.Error:new(response["status-line"])
      err:setRetry(true)
      return false, err
    end

    -- Checking for ~= 401 *should* work to
    -- but gave me a number of false positives last time I tried.
    -- We decided to change it to ~= 4xx.
    if ( response.status < 400 or response.status > 499 ) then
      return true, creds.Account:new( username, password, creds.State.VALID)
    end
    return false, brute.Error:new( "Incorrect password" )
  end,

  disconnect = function( self )
    return true
  end,

  check = function( self )
    return true
  end,

}


action = function( host, port )
  local status, result
  local path = stdnse.get_script_args("http-brute.path") or "/"
  local method = string.upper(stdnse.get_script_args("http-brute.method") or "GET")

  if ( not(path) ) then
    return "  \n  ERROR: No path was specified (see http-brute.path)"
  end

  local response = http.generic_request( host, port, method, path, { no_cache = true } )

  if ( response.status ~= 401 ) then
    return ("  \n  Path \"%s\" does not require authentication"):format(path)
  end

  -- check if digest or ntlm auth is required
  local digestauth, ntlmauth = false, false
  local h = response.header['www-authenticate']
  if h then
    h = h:lower()
    if string.find(h, 'digest.-realm') then
      digestauth = true
    end
    if string.find(h, 'ntlm') then
      ntlmauth = true
    end
  end

  local engine = brute.Engine:new(Driver, host, port, {method=method, path=path, digestauth=digestauth, ntlmauth = ntlmauth})
  engine.options.script_name = SCRIPT_NAME

  status, result = engine:start()

  return result
end
