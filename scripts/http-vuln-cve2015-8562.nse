local http = require "http"
local table = require "table"
local shortport = require "shortport"
local slaxml = require "slaxml"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[

]]

---
-- @usage
-- nmap --script http-webdav-scan -p80,8080 <target>
--
-- @output
--
-- @args path The path to start in; eg, <code>"/web/"</code> will try <code>"/web/xxx"</code>.
-- @args useragent The user agent to send the requests with.
--
-- @xmloutput


-----------------------------------------------------------------------

author = "Gyanendra Mishra"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {
  "exploit",
  "intrusive",
  "vuln",
}


portrule = shortport.http


function action (host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local php_version = nil
  local vulnerable = false
  local normalized_path = nil
  local joomla_version = nil
  local ubuntu_version = nil
  local is_deb=nil
  local is_php_vulnerable=nil

  local response = http.get(host, port, path)
  if response and response.status ~= 200 then
    return nil
  end

  -- what if this header is removed?
  if not response.header['x-powered-by'] then
    return nil
  else
    php_version =  string.match(response.header['x-powered-by'],'PHP%/([%d%.]+)')
    ubuntu_version = string.match(response.header['x-powered-by'],'ubuntu([%d%.]+)') or false
    is_deb = string.match(response.header['x-powered-by'],'deb') or false
    stdnse.debug1(php_version)
    stdnse.debug1(response.header['x-powered-by'])
  end

  if is_deb then
    if php_version > '5.4.45' then
      is_php_vulnerable=false
    --confirm the below check once
    elseif php_version > '5.4.45' and response.header['x-powered-by']:match('7[u%.]1') then
      is_php_vulnerable=false
    else
      is_php_vulnerable=true
    end
  elseif ubuntu_version then
    if php_version > '5.5.9' then
      is_php_vulnerable=false
    elseif php_version=='5.5.9' and ubuntu_version >= '4.13' then
      is_php_vulnerable=false
    elseif php_version=='5.3.10' and ubuntu_version >= '3.20' then
      is_php_vulnerable=false
    else
      is_php_vulnerable=true
    end
  elseif php_version < '5.4.44' then
    is_php_vulnerable=true
  elseif php_version>= '5.5.0' and php_version<='5.5.28' then
    is_php_vulnerable=true
  elseif php_version>= '5.6.0' and php_version<='5.6.12' then
    is_php_vulnerable=true
  end

  if not is_php_vulnerable then
    stdnse.debug1('This version of PHP looks safe!')
    return nil
  end
        

  local paths = {'/', '/administartor/'}
  local joomla_and_online = false

  for _, subpath in pairs(paths) do
    normalized_path = string.gsub(path .. subpath, "//", "/")
    response = http.get(host, port, normalized_path)
    if response and response.status==200 then
      if string.match(response.body, '<meta name="generator" content="Joomla!') then
        joomla_and_online = true
        break
      end
    end
  end

  if not joomla_and_online then
    stdnse.debug1("Joomla not found on target!")
    return nil
  end

  normalized_path = string.gsub(path .. 'administrator/manifests/files/joomla.xml', '//', '/')
  response = http.get(host, port, normalized_path)
  if response and response.status == 200 then
    local parser = slaxml.parser:new()
    parser._call = {startElement = function(name)
        if name =='version' then parser._call.text = function(content) joomla_version = content end end end,
        closeElement = function(name) parser._call.text = function() return nil end end
    }
    parser:parseSAX(response.body, {stripWhitespace=true})
  end

  if joomla_version < '3.4.6' then

    local vuln_table = {
      title = "Joomla HTTP Header Unauthenticated Remote Code Execution",
      state = vulns.STATE.VULN,
      risk_factor = "High",
      references = {
        'https://blog.sucuri.net/2015/12/joomla-remote-code-execution-the-details.html',
        'https://blog.sucuri.net/2015/12/remote-command-execution-vulnerability-in-joomla.html',
        'https://developer.joomla.org/security-centre/630-20151214-core-remote-code-execution-vulnerability.html'
      },
      IDS = {
        CVE = 'CVE-2015-8562'
      },
      scores = {
        CVSS2 =  '7.5'
      },
      description = [[Joomla suffers from an unauthenticated remote code execution that affects all versions from 1.5.0 to 3.4.5.]]
    }

    local report = vulns.Report:new(SCRIPT_NAME, host, port)


    return report:make_output(vuln_table)
  end

end

