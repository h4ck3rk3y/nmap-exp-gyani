local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local base64 = require "base64"
local math = require "math"
local table = require "table"

description = [[
A script to check if a WebDAV installation has insecure permsisions.

The script starts by testing the MKCOL method and creating a directory. It then proceeds
to upload multiple files of multiple extensions and check if they are executable. Then we
check if the files are renamable and if the extension can be changed by using MOVE.

It's based on the  script ideas page.
  *https://secwiki.org/w/Nmap/Script_Ideas# http-webdav
This script takes inspiration from the various scripts listed here:
  *http://carnal0wnage.attackresearch.com/2010/05/more-with-metasploit-and-webdav.html
  *https://github.com/sussurro/Metasploit-Tools/blob/master/modules/auxiliary/scanner/http/webdav_test.rb
  *http://code.google.com/p/davtest/
]]

---
-- @usage
-- nmap --script http-webdav -p80,8080 <target>
--
-- @args folder The folder to start in; eg, <code>"/web/"</code> will try <code>"/web/xxx"</code>.
--
-- @output
-- | http-webdav-perms: 
-- |   Uploadable Files: 
-- |     shtml
-- |     aspx
-- |     txt
-- |     pl
-- |     jhtml
-- |     jsp
-- |     asp
-- |     php
-- |     html
-- |     cfm
-- |     cgi
-- |   Executable Files: 
-- |     txt
-- |     html
-- |   Renamable Files: 
-- |     shtml
-- |     aspx
-- |     pl
-- |     jhtml
-- |     jsp
-- |     asp
-- |     php
-- |     html
-- |     cfm
-- |     cgi
-- |   Executable after rename: 
-- |_    html
--
-- @xmloutput
-- <table key="Uploadable Files">
--   <elem>cgi</elem>
--   <elem>cfm</elem>
--   <elem>shtml</elem>
--   <elem>jsp</elem>
--   <elem>html</elem>
--   <elem>aspx</elem>
--   <elem>txt</elem>
--   <elem>jhtml</elem>
--   <elem>asp</elem>
--   <elem>pl</elem>
--   <elem>php</elem>
-- </table>
-- <table key="Executable Files">
--   <elem>html</elem>
--   <elem>txt</elem>
-- </table>
-- <table key="Renamable Files">
--   <elem>cgi</elem>
--   <elem>cfm</elem>
--   <elem>shtml</elem>
--   <elem>jsp</elem>
--   <elem>html</elem>
--   <elem>aspx</elem>
--   <elem>jhtml</elem>
--   <elem>asp</elem>
--   <elem>pl</elem>
--   <elem>php</elem>
-- </table>
-- <table key="Executable after rename">
--   <elem>html</elem>
-- </table>
-----------------------------------------------------------------------

author = "Gyanendra Mishra"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {
  "exploit",
  "intrusive"
}


portrule = shortport.http

local files = {
  ['asp'] = '<html><body><% response.write (!N1! * !N2!) %>',
  ['aspx'] = '<html><body><% response.write (!N1! * !N2!) %>',
  ['cfm'] = '<cfscript>WriteOutput(!N1!*!N2!);</cfscript>',
  ['cgi'] = "#!/usr/bin/perl\nprint \"Content-Type: text/html\n\r\n\r\" . !N1! * !N2!;",
  ['html'] = '!S1!<br />',
  ['jhtml'] = '<%= System.out.println(!N1! * !N2!); %>',
  ['jsp'] = '<%= System.out.println(!N1! * !N2!); %>',
  ['php'] = '<?php print !N1! * !N2!;?>',
  ['pl'] = "#!/usr/bin/perl\nprint \"Content-Type: text/html\n\r\n\r\" . !N1! * !N2!;",
  ['shtml'] = '<!--#echo var="DOCUMENT_URI"--><br /><!--#exec cmd="echo !S1!"-->',
  ['txt'] = '!S1!',
}

local jpg_file = base64.dec("/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAAA//EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AR//Z")

local function create_dir (host, port, dir)
  local options = {
    header = {
      ["Content-Length"] = 0,
    },
  }
  local response = http.generic_request(host, port, 'MKCOL', dir ..'/', options)

  if response and response.status and response.status >= 200 and response.status <= 300 then
    return true
  end
  return false
end

local function delete_dir (host, port, dir)
  local options = {
    header = {
      ["Content-Length"] = 0,
    },
  }
  local response = http.generic_request(host, port, "DELETE", dir .. '/', options)
  if response and response.status >= 200 and response.status <= 300 then
    return true
  end
  return false
end

local function check_extensions (host, port, path)
  local result = {}
  for extension, payload in pairs(files) do
    stdnse.debug2('Trying to upload extension %s', extension)
    local answer = nil
    local fname = stdnse.generate_random_string(15, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    local file_path = path .. "/" .. fname .. "." .. extension
    if payload:find '!N1!' then
      local n1 = math.random(10000) / 100 * 10
      local n2 = math.random(10000) / 100 * 10
      answer = tostring(n1 * n2)
      payload = payload:gsub('!N1', n1)
      payload = payload:gsub('!N2', n2)
    else
      answer = stdnse.generate_random_string(25, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
      payload = payload:gsub('!S1!', answer)
    end
    payload = payload .. "\n\n"
    local options = {
      header = {
        ["Content-Length"] = payload:len(),
      },
      timeout = 10,
    }
    local response = http.put(host, port, file_path, options, payload)
    if not response or response.status ~= 201 then
      table.insert(result, {
          extension,
          false,
          false,
        })
    else
      response = http.get(host, port, file_path)
      if not response or response.status ~= 200 or not response.body:find(answer) or response.body:find "#exec" then
        table.insert(result, {
            extension,
            true,
            false,
          })
      else
        table.insert(result, {
            extension,
            true,
            true,
          })
      end
    end
  end
  return result
end

local function check_rename (host, port, path)
  local result = {}
  for extension, payload in pairs(files) do
    stdnse.debug2("Trying to rename extension %s", extension)
    local answer = nil
    local fname = stdnse.generate_random_string(15, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    local file_path = path .. "/" .. fname .. ".txt"
    file_path = file_path:gsub('//', '/')

    local file_path_move = nil
    if host.targetname then
      file_path_move = host.targetname .. "/" .. path .. "/" .. fname .. "." .. extension .. ';.jpg'
    else
      file_path_move = host.ip .. "/" .. path .. "/" .. fname .. "." .. extension .. ';.jpg'
    end
    file_path_move = 'http://' .. file_path_move:gsub('//', '/')

    if payload:find '!N1!' then
      local n1 = math.random(10000) / 100 * 10
      local n2 = math.random(10000) / 100 * 10
      answer = tostring(n1 * n2)
      payload = payload:gsub('!N1', n1)
      payload = payload:gsub('!N2', n2)
    else
      answer = stdnse.generate_random_string(25, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
      payload = payload:gsub('!S1!', answer)
    end

    payload = jpg_file .. payload .. '\n\n'
    local options = {
      header = {
        ["Content-Length"] = payload:len(),
      },
      timeout = 5,
    }
    local response = http.put(host, port, file_path, options, payload)
    if not response or response.status ~= 201 then
      table.insert(result, {
          extension,
          false,
          false,
        })
    else
      options = {
        header = {
          ["Destination"] = file_path_move,
        },
        timeout = 5,
      }
      response = http.generic_request(host, port, "MOVE", file_path, options)
      if not response or not (response.status == 204 or response.status == 201) then
        table.insert(result, {
            extension,
            false,
            false,
          })
      else
        response = http.get(host, port, path .. "/" .. fname .. "." .. extension .. ';.jpg')
        if not response or response.status ~= 200 or not response.body:find(answer) or response.body:find "#exec" then
          table.insert(result, {
              extension,
              true,
              false,
            })
        else
          table.insert(result, {
              extension,
              true,
              true,
            })
        end
      end
    end
  end
  return result
end

function action (host, port)

  local path = stdnse.get_script_args(SCRIPT_NAME .. ".folder") or '/'
  local output = stdnse.output_table()
	
  local random_string = stdnse.generate_random_string(10, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
  local test_dir = path .. '/' .. 'WebDavTest_' .. random_string
  test_dir = test_dir:gsub('//', '/')
  -- creating a random named folder
  stdnse.debug1("Attempting to create folder %s", test_dir)
  if create_dir(host, port, test_dir) then
    stdnse.debug1 "The HOST is WRITABLE"
  else
    stdnse.debug1 "The HOST is not WRITABLE"
    return
  end
  -- checking uploadable extensions
  stdnse.debug1 "Checking extensions for upload and execution"
  local results_1 = check_extensions(host, port, test_dir)
  -- checking renamable extensions
  stdnse.debug1 "Checking if rename is possible or not"
  local results_2 = check_rename(host, port, test_dir)

  -- deleting the mess we just created.
  stdnse.debug1("Deleting directory %s", test_dir)
  if delete_dir(host, port, test_dir) then
    stdnse.debug1("Delete Succesfull")
  end

  local uploadable = {}
  local executable = {}
  local renamable_ex = {}
  local renamable = {}


  for _, result in pairs(results_1) do
    if result[2] == true then
      table.insert(uploadable, result[1])
    end
    if result[3] == true then
      table.insert(executable, result[1])
    end
  end

  for _, result in pairs(results_2) do
    if result[2] == true then
      table.insert(renamable, result[1])
    end
    if result[3] == true then
      table.insert(renamable_ex, result[1])
    end
  end

  if #uploadable > 0 then output['Uploadable Files'] = uploadable end
  if #executable > 0 then output['Executable Files'] = executable end
  if #renamable > 0 then output['Renamable Files'] = renamable end
  if #renamable_ex >0 then output['Executable after rename'] = renamable_ex end
  if #output > 0 then return output else return nil end
end

