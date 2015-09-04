local http = require "http"
local table = require "table"
local shortport = require "shortport"
local stdnse = require "stdnse"
local slaxml = require "slaxml"

description = [[
Provides information about OpenTracker bittorent tracker implementation.
The script queries the URI 'stats?mode=everything' parses the xml and
gives out stats like ]]


---
-- @usage
-- nmap --script opentracker-stats -p80,8080 <target>
--
-- @args path The relative path to access. <code>'/web'</code> will look in the web directory.
--
--
-- @output
-- | opentracker-stats: 
-- |   Tracker ID: 279881261
-- |   Version: $Source$: $Revision$
-- |   Uptime: 20640978
-- |   Torrents: 
-- |     Mutex Count: 12
-- |     Iterator Count: 12
-- |   Peers: 34
-- |   Seeds: 0
-- |   Completed: 2381
-- |   TCP: 
-- |     Scrape: 0
-- |     Accept: 313296698
-- |     Announce: 156626542
-- |   UDP: 
-- |     Missmatch: 0
-- |     Overall: 0
-- |     Announce: 0
-- |     Connect: 0
-- |   HTTP Errors: 
-- |     500 Internal Server Error: 0
-- |     400 Not Modest: 0
-- |     400 Parse Error: 250
-- |     400 Invalid Parameter: 10
-- |     302 Redirect: 0
-- |     403 Access Denied stats: 0
-- |     404 Not found: 2418
-- |     400 Invalid Parameter (compact=0): 0
-- |_  Mutex Stall: 3
--
-- @xmloutput
-- <elem key="Tracker ID">279881261</elem>
-- <elem key="Version">$Source$: $Revision$</elem>
-- <elem key="Uptime">20641106</elem>
-- <table key="Torrents">
--   <elem key="Iterator Count">12</elem>
--   <elem key="Mutex Count">12</elem>
-- </table>
-- <elem key="Peers">34</elem>
-- <elem key="Seeds">0</elem>
-- <elem key="Completed">2381</elem>
-- <table key="TCP">
--   <elem key="Scrape">0</elem>
--   <elem key="Announce">156626576</elem>
--   <elem key="Accept">313296768</elem>
-- </table>
-- <table key="UDP">
--   <elem key="Connect">0</elem>
--   <elem key="Announce">0</elem>
--   <elem key="Overall">0</elem>
--   <elem key="Missmatch">0</elem>
-- </table>
-- <table key="HTTP Errors">
--   <elem key="500 Internal Server Error">0</elem>
--   <elem key="400 Invalid Parameter">10</elem>
--   <elem key="400 Parse Error">250</elem>
--   <elem key="302 Redirect">0</elem>
--   <elem key="400 Invalid Parameter (compact=0)">0</elem>
--   <elem key="400 Not Modest">0</elem>
--   <elem key="403 Access Denied stats">0</elem>
--   <elem key="404 Not found">2418</elem>
-- </table>
-- <elem key="Mutex Stall">3</elem>

-----------------------------------------------------------------------

author = "Gyanendra Mishra"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {
  "safe",
  "discovery",
  "default",
}


portrule = shortport.http

local type_1_elements = {
["tracker_id"] = "Tracker ID",
["version"] = "Version",
["uptime"] = "Uptime",}

local type_2_elements = {
["peers"] = "Peers",
["seeds"] = "Seeds",
["completed"] = "Completed"  
}

function action (host, port)
  local output = stdnse.output_table()
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or ''
  local response = http.get(host, port, path .. '/stats?mode=everything')
  
  if response.status and response.status == 200 then

    -- we cherry pick the stats element
    local dom = slaxml.parseDOM(response.body, {stripWhitespace=true}).kids[2].kids
    for _, element in pairs(dom) do

      if type_1_elements[element.name] then
        output[type_1_elements[element.name]] = element.kids[1].value
      
      elseif element.name == "torrents" then
        output["Torrents"] = {}
        output["Torrents"]["Mutex Count"] = element.kids[1].kids[1].value
        output["Torrents"]["Iterator Count"] = element.kids[2].kids[1].value

      elseif type_2_elements[element.name] then
        output[type_2_elements[element.name]] = element.kids[1].kids[1].value
        
      elseif element.name == "connections" then
        output["TCP"] = {
          ["Accept"] = element.kids[1].kids[1].kids[1].value,
          ["Announce"] = element.kids[1].kids[2].kids[1].value,
          ["Scrape"] = element.kids[1].kids[3].kids[1].value
        }
        output["UDP"] = {
          ["Overall"] = element.kids[2].kids[1].kids[1].value,
          ["Connect"] = element.kids[2].kids[2].kids[1].value,
          ["Announce"] = element.kids[2].kids[3].kids[1].value,
          ["Missmatch"] = element.kids[2].kids[4].kids[1].value
        }
      
      elseif element.name == "debug" then
        local http_error = element.kids[2].el
        output["HTTP Errors"] = {}
        for _, errors in pairs(http_error) do
          output["HTTP Errors"][errors.attr["code"]] = errors.kids[1].value
        end
        output["Mutex Stall"] = element.kids[3].kids[1].kids[1].value
      end
    
    end
    if #output > 0 then return output end
  end
end

