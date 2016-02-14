local comm  = require "comm"
local gps = require "gps"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"


description = [[
Retrieves GPS time, coordinates and speed from the GPSD network daemon.
If the script is running in NG mode then it Retrieves device and version information from a listening GPSD-NG daemon.
gpsd is a service daemon that monitors one or more GPSes or AIS receivers attached to a host computer through serial or USB ports, making all data on the location/course/velocity of the sensors available to be queried on TCP port 2947 of the host computer.
For more information about GPSD-NG, see:
http://gpsd.berlios.de/gpsd.html
http://en.wikipedia.org/wiki/Gpsd
http://gpsd.berlios.de/protocol-evolution.html
]]

---
-- @usage
-- nmap --script gpsd-info --script-args gpsd-info.timeout=5 -p <port> <host>
--
-- @args gpsd-info.timeout
--       Set timeout. The default value is 10.
-- @args gpsd-info.ng Scan for gpsd-ng devices. Default false.
--
-- @output
-- PORT   STATE SERVICE   REASON
-- 2947/tcp open  gpsd-ng syn-ack
-- | gpsd-ng-info:
-- |     VERSION:
-- |      rev = 2011-04-15T13:37:50.73
-- |      release = 3.0~dev
-- |      proto_major = 3
-- |      proto_minor = 4
-- |     DEVICES:
-- |         DEVICE:
-- |          parity = N
-- |          path = /dev/ttyS0
-- |          subtype = GSW3.2.4_3.1.00.12-SDK003P1.00a
-- |          stopbits = 1
-- |          flags = 1
-- |          driver = SiRF binary
-- |          bps = 38400
-- |          native = 1
-- |          activated = 2011-05-15T11:11:34.450Z
-- |          cycle = 1
-- |         DEVICE:
-- |          parity = N
-- |          path = /dev/cuaU0
-- |          stopbits = 1
-- |          flags = 1
-- |          driver = uBlox UBX binary
-- |          bps = 9600
-- |          mincycle = 0.25
-- |          native = 1
-- |          activated = 2011-05-15T01:19:34.200Z
-- |_         cycle = 1
--
-- @changelog
-- 2011-06-18 - v0.2 - Brendan Coles - itsecuritysolutions.org added gpsd-ng support.
--
-- @TODO
-- add xmloutput

author = "Patrik Karlsson, Brendan Coles [itsecuritysolutions.org]"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service (2947, "gpsd-ng", {"tcp"})

local function updateData(gpsinfo, entry)
  for k, v in pairs(gpsinfo) do
    if ( entry[k] and 0 < #tostring(entry[k]) ) then
      gpsinfo[k] = entry[k]
    end
  end
end

local function hasAllData(gpsinfo)
  for k, v in pairs(gpsinfo) do
    if ( k ~= "speed" and v == '-' ) then
      return false
    end
  end
  return true
end

--- parse GPSD-NG data in table format
-- This function parses replies to GPSD-NG commands:
-- "?VERSION;" and "?DEVICES;" -- TODO: "?POLL;"
-- @param data a table containg JSON data
-- @return a table containing GPSD-NG in NSE output format
local function parseGPSDNG(data)

  local result = {}

  -- use class nodes as table keys
  if data["class"] then table.insert(result,("%s:"):format(tostring(data["class"]))) end

  -- extract node properties
  for k,v in pairs(data) do
    if type(v) ~= 'table' and k ~= "class" then
      table.insert(result,(("\t%s = %s"):format(tostring(k), tostring(v))))
    end
  end

  -- parse child node of type table
  for k,v in pairs(data) do
    if type(v) == 'table' then table.insert(result,parseGPSDNG(v)) end
  end

  return result

end

action = function(host, port)

  local result = stdnse.output_table()
  local timeout = stdnse.parse_timespec((stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))) or 10
  local ng = stdnse.get_script_args(SCRIPT_NAME .. ".ng") or false
  local  command  = nil

  if ng then
  -- Connect and retrieve "?DEVICES;" data
    command = '?DEVICES;'
  else
    command = '?WATCH={"enable":true,"nmea":true}\r\n'
  end

  stdnse.debug1(("%s: Connecting to %s:%s [Timeout: %ss]"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, timeout))
  local status, data = comm.exchange(host, port, command,{lines=3, proto=port.protocol, timeout=timeout*1000})

  if not status or not data then
    stdnse.debug1(("%s: Retrieving data from %s:%s failed [Timeout expired]"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
    return
  end

  if ng then
    -- Convert received JSON data to table
    stdnse.debug1(("%s: Parsing JSON data from %s:%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
    for line in string.gmatch(data, "[^\n]+") do
      local status, json_data = json.parse(line)
      if not status or not json_data or not json_data["class"] then
        stdnse.debug1(("%s: Failed to parse data from %s:%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
        return
      end
      table.insert(result, parseGPSDNG(data))
    end
  else
    local gpsinfo = {
      longitude = "-",
      latitude = "-",
      speed = "-",
      time  = "-",
      date  = "-",
    }
    for line in string.gmatch(data, "[^\r\n]+") do
      status, entry = gps.NMEA.parse(line)
      if status then
        updateData(gpsinfo, entry)
      end
    end
    if not hasAllData(gpsinfo) then
      stdnse.debug1('Incomplete or no data received!')
      return
    end
    result['Time of Fix'] = stdnse.format_timestamp(gps.Util.convertTime(gpsinfo.date, gpsinfo.time))
    result['Coordinates'] = ("%.4f,%.4f"):format(tonumber(gpsinfo.latitude), tonumber(gpsinfo.longitude))
    result['Speed'] = ("%s knots"):format(gpsinfo.speed)
  end

  -- Return results
  return result
end
