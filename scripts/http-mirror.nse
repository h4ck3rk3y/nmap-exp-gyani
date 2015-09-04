local httpspider = require "httpspider"
local io = require "io"
local os = require "os"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local url_lib = require "url"

description = [[
Spiders a website and creates an offline mirror.
]]

-- LIMITATIONS
-- spider catches js functions! and other non existent links
-- all paths are currently relative to the current user directory (/home/<username>/)!
-- works in linux based operating systems only. need to add osx and windows support.
-- some downloaded urls aren't getting localized.
-- some urls need to be encoded to be read.
-- images and other extensions are blocked. should they be allowed?

-- TODO
-- #tag handling
-- windows/osx support
-- extension handling
-- getting rid of all limitations.

-- please send in comments and suggestions.

--@args convert-links set true will convert links to all downloaded pages to local links. defalut false.
--@args path to store in relative to home directory
-- all the usual httpspider args follow

--@usage nmap -p 80 --script mirrors --script-args convert-links='true' nmap.org
-- @output
-- Host is up, received syn-ack (0.00039s latency).
-- Scanned at 2015-03-01 00:37:56 IST for 135s
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | mirrors: 
-- |_  Successfully mirrred the website at ///home/neo/nmap.org

-- send any feed back to anomaly.the()gmail.com

author = "Gyanendra Mishra"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

-- escapes the url to be replaced so that gsub doesn't throw error
local function  cleanString(str)
  return str:gsub("[%(%)%.%%%+%-%*%?%[%]%^%$]", function(c) return "%" .. c end)
end

-- escapes % in replaced url
local function  cleanReplacementString(str)
  return str:gsub("[%%]", function(c) return "%" .. c end)
end

-- makes urls like '/index' into www.example.com/index
local function makeRelativeAbsolute(current_url ,body)
   local patterns = {
      '[hH][rR][eE][fF]%s*=%s*[\'"]%s*([^"^\']-)%s*[\'"]',
      '[hH][rR][eE][fF]%s*=%s*([^\'\"][^%s>]+)',
      '[sS][rR][cC]%s*=%s*[\'"]%s*([^"^\']-)%s*[\'"]',
      '[sS][rR][cC]%s*=%s*([^\'\"][^%s>]+)',
      '[aA][cC][tT][iI][oO][nN]%s*=%s*[\'"]%s*([^"^\']+%s*)[\'"]',
    }
    local base_hrefs = {
      '[Bb][Aa][Ss][Ee]%s*[Hh][Rr][Ee][Ff]%s*=%s*[\'"](%s*[^"^\']+%s*)[\'"]',
      '[Bb][Aa][Ss][Ee]%s*[Hh][Rr][Ee][Ff]%s*=%s*([^\'\"][^%s>]+)'
    }

    --messed up spider check for 404s or 200s while Replacing?
    local base_href
    for _, pattern in ipairs(base_hrefs) do
      base_href = body:match(pattern)
      if ( base_href ) then
        break
      end
    end
    for _, pattern in ipairs(patterns) do
      for l in body:gmatch(pattern) do
        local link = l
        if (l:sub(1,2)=="//") then
          stdnse.print_debug(1,"1\tReplacing\t%s\nwith\t%s",l,'http://'..(l:sub(3)))
          body = body:gsub('"%s*'..cleanString(l) .. '%s*"','"http://'..cleanReplacementString(l:sub(3)) .. '"')
          body = body:gsub("'%s*"..cleanString(l) .. "%s*'","'http://"..cleanReplacementString(l:sub(3)).. "'")
        elseif  ( not(httpspider.LinkExtractor.isAbsolute(l)) ) then
          link = httpspider.LinkExtractor.createAbsolute(httpspider.URL:new(current_url), l, base_href)
          if not(link:find("'")) and not(link:find('"')) then
            stdnse.print_debug(1,"2\tReplacing\t%s\nwith\t%s",l,(link))
            body = body:gsub('"%s*'..cleanString(l) .. '%s*"','"'..(link) .. '"')
            body = body:gsub("'%s*"..cleanString(l) .. "%s*'","'"..(link) .. "'")
          end
        end
      end
    end
    return body
end

--converts urls in files downloaded into local urls. done at the end so that we know what needs to be localized.
local function localizeUrls(processed_urls)
  for _,url_ob in pairs(processed_urls) do
    local file_read,err_read = io.open(url_ob['processed_url'],"r")
    if file_read then
      local content = file_read:read("*all")
      for _,url_ob_temp in pairs(processed_urls) do
        -- converts the http version of the link
        content = content:gsub('"%s*'..cleanString(url_ob_temp['url']):gsub("https://",'http://')..'"','"'.. (url_ob_temp['processed_url'])..'"')
        content = content:gsub("'%s*"..cleanString(url_ob_temp['url']):gsub("https://",'http://').."'","'".. (url_ob_temp['processed_url']).."'")
        -- converts the https version of the links
        content = content:gsub('"%s*'..cleanString(url_ob_temp['url'])..'"','"'.. (url_ob_temp['processed_url'])..'"')
        content = content:gsub("'%s*"..cleanString(url_ob_temp['url']).."'","'".. (url_ob_temp['processed_url']).."'")
      end
      file_read:close()
      local file_write,err_write = io.open(url_ob['processed_url'],'w')
      if file_write then
        file_write:write(content)
        file_write:close()
      else
        stdnse.print_debug(1,"Error in writing ...%s",err_write)
      end
    else
      stdnse.print_debug(1,"Error in reading ...%s",err_read)
    end
  end
end

--create directory using -p parameter
local function  createDirectory(path)
  stdnse.print_debug(3,"Creating path...%s",path)
  os.execute("mkdir -p "..path)
end

--saves page if body and status are 200
local function  save_page(body,current_url,path)
  local url = httpspider.URL:new(current_url)
  local file_path = path ..  url:getDir()
  createDirectory(file_path)
  if url:getDir() == url:getFile() then
    file_path = file_path .. "index.html"
  else
    file_path = path .. url:getFile()
  end
  local file,err = io.open(file_path,"w")
  if file  then
    stdnse.print_debug(1,"Saving to ...%s",file_path)
    file:write(body)
    file:close()
    return true,file_path
  else
    stdnse.print_debug(1,"Error encountered in  save_page was .. %s",err)
    return false
  end
end

action = function(host, port)
  -- read script specific arguments like path and convert-links
  local path = stdnse.get_script_args("http-mirror.path") or tostring(host.targetname)
  path = path:gsub('/','')
  path = '//' .. os.getenv("HOME") .. '/' .. path
  local crawler = httpspider.Crawler:new(host, port, nil, { scriptname = SCRIPT_NAME,maxdepth=10,maxpagecount=20})
  local convert_links = stdnse.get_script_args("http-mirror.convert-links") or false
  -- set timeout to 10 seconds
  crawler:set_timeout(10000)
  local processed_urls = {}
  while(true) do
    local status, r = crawler:crawl()
    -- if the crawler fails it can be due to a number of different reasons
    -- most of them are "legitimate" and should not be reason to abort
    if ( not(status) ) then
      if ( r.err ) then
        return stdnse.format_output(true, "ERROR: %s", r.reason)
      else
        break
      end
    end
    local current_url  = tostring(r.url)
    local body = r.response.body
    -- convert all relative links in body to absolute links and ads the downloaded url to the table.
    -- scraper grabs random links. hence the find checks.need to work on this.
    if body and r.response.status == 200 and not(current_url:find("'")) and not(current_url:find('"')) then
      stdnse.print_debug(1,"Processing url.......%s",current_url)
      body =  makeRelativeAbsolute(current_url,body)
      local stat,saved_at  = save_page(body,current_url,path)
      if  stat then
        local mini = {}
        mini['url']= current_url
        mini['processed_url'] = saved_at
        table.insert(processed_urls,mini)
      end
    else
      if body then
        stdnse.print_debug(1,"No Body For: %s",current_url)
      elseif r.response.status ~= 200 then
        stdnse.print_debug(1,"Status not 200 For: %s",current_url)
      else
        stdnse.print_debug(1,"False URL picked by spider!: %s",current_url)
      end
    end
  end
  if convert_links ~= false then
    localizeUrls(processed_urls)
  end
  return stdnse.format_output(true,"Successfully mirrred the website at "..path)
end