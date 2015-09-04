local http = require "http"
local httpspider = require "httpspider"
local io = require "io"
local lfs = require "lfs"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
The script is used to fetch interesting resources like robots.txt,crossdomain.xml from servers.
]]

---
-- @usage nmap --script http-fetch <target>
--
-- @args http-fetch.destination - The full path of the directory to save the file(s) to preferably with the trailing slash.
-- @args http-fetch.files - The name of the file(s) to be fetched.
-- @args http-fetch.url  - The directory to look for the file(s) in.
-- @args http.builtins - A set of builtin filetypes to be downloaded.
-- @args http.everything - If Set True then creates a mirror at destination.
-- @args http.pattern - A table of patterns. For example if the password is ".jpg" then it will download all jpg files.
-- @output
-- | http-fetch: 
-- |   Successfully Downloaded: 
-- |     crossdomain.xml as localhost-8000-crossdomain.xml
-- |_    clientaccesspolicy.xml as localhost-8000-clientaccesspolicy.xml
--
-- @xmloutput
-- <table key="Successfully Downloaded">
--   <elem>crossdomain.xml as localhost-8000-crossdomain.xml</elem>
--   <elem>clientaccesspolicy.xml as localhost-8000-clientaccesspolicy.xml</elem>
-- </table>

author = "Gyanendra"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe"}

portrule = shortport.http

local SEPARATOR =  lfs.get_path_separator()

local resources = {
  ['robots'] = 'robots.txt',
  ['policy'] = {'crossdomain.xml', 'clientaccesspolicy.xml'}
}

local function save_file_1(content, file_name, destination)
  if destination:sub(-1) == '\\' or destination:sub(-1) == '/' then
    file_name = destination .. stdnse.filename_escape(file_name)
  else
    file_name = destination .. SEPARATOR  .. stdnse.filename_escape(file_name)
  end
  local file, err_message = io.open(file_name, "w")
  if ( file ) then
    file:write(content)
    file:close()
    return true
  else
    return false, err_message
  end
end

local function insert(files, data)
  if type(data) == 'table' then
    for _, value in pairs(data) do
      if not stdnse.contains(files, value) then
        table.insert(files, value)
      end
    end
  else
    if not stdnse.contains(files, data) then
      table.insert(files, data)
    end
  end
end

local function build_path(file, url)
  local path = '/' .. url .. '/' .. file
  return path:gsub('//', '/')
end


-- this function creates the given path.
-- say its trying to create /a/b/c/d/
-- if d doesn't exist it creates c first
-- if c doesn't exist then it creates b and so on.
local function create_directory(path)
  local status, err = lfs.mkdir(path)
  if status then
    stdnse.debug2("Created path %s", path)
    return true
  elseif err == "No such file or directory" then
    stdnse.debug2("Parent directory doesn't exist %s", path)
    local index  = string.find(path:sub(1, path:len() -1), SEPARATOR .. "[^" .. SEPARATOR .. "]*$")
    local sub_path = path:sub(1, index)
    stdnse.debug2("Trying path...%s", sub_path)
    create_directory(sub_path)
    lfs.mkdir(path)
  end
end

local function  save_file_2(body, current_url, path)
  local url = httpspider.URL:new(current_url
)
  local file_path = path ..  url:getDir()
  create_directory(file_path)
  if path:sub(-1) == '\\' or path:sub(-1) == '/' then
    path = path
  else
    path = path .. SEPARATOR
  end
  if url:getDir() == url:getFile() then
    file_path = file_path .. "index.html"
  else
    file_path = path .. url:getDir() .. stdnse.filename_escape(url:getFile():gsub(url:getDir(),""))
  end
  file_path = file_path:gsub("//", "/")
  file_path = file_path:gsub("\\/", "\\")
  -- in windows extensions are required. say the url is http://example.com/abcd
  -- we save it as abcd.html on windows, on unix this doesn't matter.
  if not url:getFile():find(".") then
    file_path = file_path .. ".html"
  end
  local file,err = io.open(file_path,"r")
  if not err then
    stdnse.debug1("File Already Exists")
    return true, file_path
  else
    local file,err = io.open(file_path,"w")
    if file  then
      stdnse.debug1("Saving to ...%s",file_path)
      file:write(body)
      file:close()
      return true, file_path
    else
      stdnse.debug1("Error encountered in  saving file was .. %s",err)
      return false, err
    end
  end
end

local function download_everything(host, port, destination, url, patterns)
  local output = stdnse.output_table()
  local crawler = httpspider.Crawler:new(host, port, url, { scriptname = SCRIPT_NAME, maxdepth = 5, maxpagecount = 10, noblacklist = true})
  crawler:set_timeout(10000)
  while(true) do
    local status, r = crawler:crawl()
    if ( not(status) ) then
      if ( r.err ) then
        return stdnse.format_output(true, "ERROR: %s", r.reason)
      else
        break
      end
    end
    local body = r.response.body
    local current_url = tostring(r.url)
    if body and r.response.status == 200 and patterns then
      if type(patterns) ~= "table" then
        patterns = {patterns}
      end
      local url = httpspider.URL:new(current_url)
      for _, pattern in pairs(patterns) do
        if url:getFile():find(pattern) then
          local status, err_message = save_file_1(r.response.body, url:getFile(), destination)
          if status then
            output['Match For Pattern ' .. pattern] = output['Match For Pattern ' .. pattern] or {}
            table.insert(output['Match For Pattern ' .. pattern], string.format("%s as %s", current_url, url:getFile()))
          else
            output['ERROR'] = output['ERROR'] or {}
            output['ERROR'][current_url] = err_message
          end
          break
        end
      end
    elseif body and r.response.status == 200 then -- refer to mirror if errors
      stdnse.debug1("Processing url.......%s",current_url)
      local stat, path_or_err = save_file_2(body, current_url, destination)
      if stat then
        output['Successfully Downloaded'] = output['Successfully Downloaded'] or {}
        output['Successfully Downloaded'][current_url] =  path_or_err
      else
        output['ERROR'] = output['ERROR'] or {}
        output['ERROR'][current_url] = path_or_err
      end
    else
      if not r.response.body then
        stdnse.debug1("No Body For: %s",current_url)
      elseif r.response and r.response.status ~= 200 then
        stdnse.debug1("Status not 200 For: %s",current_url)
      else
        stdnse.debug1("False URL picked by spider!: %s",current_url)
      end
    end
  end
  return true, output
end

action = function(host, port)

  local destination = stdnse.get_script_args(SCRIPT_NAME..".destination") or false
  local url = stdnse.get_script_args(SCRIPT_NAME..".url") or "/"
  local files = stdnse.get_script_args(SCRIPT_NAME..'.files') or nil
  local builtins = stdnse.get_script_args(SCRIPT_NAME..'.builtins') or false
  local everything = stdnse.get_script_args(SCRIPT_NAME..'.everything') or false
  local patterns = stdnse.get_script_args(SCRIPT_NAME..'.pattern') or false
  local output = stdnse.output_table()

  if not destination then
    output.error = "Please enter the complete path of the directory to save data in."
    return output, output.error
  end

  if everything or patterns then
    local status, output_table = download_everything(host, port, destination, url)
    if status then
      if nmap.verbosity() > 1 then
        return output_table
      else
        output.result = "Successfully Downloaded Everything At: " .. destination
        return output, output.result
      end
    else
      output.result = "Error while downloading 'everything'"
      return output, output.result
    end
  end

  if files and type(files) ~= 'table' then
    files = {files}
  end

  if builtins then
    if type(builtins) ~= 'table' then
      builtins = {builtins}
    end
    for _, builtin in pairs(builtins) do
      if resources[builtin] then
        files = files or {}
        insert(files, resources[builtin])
      end
    end
  end

  if not files then
    files = {}
    insert(files, resources['robots'])
    insert(files, resources['policy'])
  end

  for _, file in pairs(files) do
    local response = http.get(host, port, build_path(file, url), nil)
    if response and response.status  and response.status == 200 then
      local save_as = host.targetname .. "-" .. tostring(port.number) .. "-" .. file
      local status, err_message = save_file_1(response.body, save_as, destination)
      if status then
        output['Successfully Downloaded'] = output['Successfully Downloaded'] or {}
        table.insert(output['Successfully Downloaded'], string.format("%s as %s", file, save_as))
      else
        output['ERROR'] = output['ERROR'] or {}
        output['ERROR'][file] = err_message
      end
    else
      stdnse.debug1("%s doesn't exist on server at %s.", file, url)
    end
  end

  if output['Successfully Downloaded'] or output['ERROR'] then return output end
end

