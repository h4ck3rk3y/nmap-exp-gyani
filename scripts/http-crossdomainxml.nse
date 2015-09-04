local http = require "http"
local stdnse = require "stdnse"
local vulns = require "vulns"
local nmap = require "nmap"
local shortport = require "shortport"
local table = require "table"
local string = require "string"

description = [[
Checks the cross-domain policy file (/crossdomain.xml) and the client-acces-policy file (/clientaccesspolicy.xml) in web applications and lists the trusted 
domains. Overly permissive settings enable Cross Site Request Forgery attacks and may allow attackers
 to access sensitive data. This script is useful to detect permissive configurations and possible 
domain names available for purchase to exploit the application.

The script queries instantdomainsearch.com to lookup the domains. This functionality is 
turned off by default, to enable it set the script argument http-crossdomainxml.domain-lookup.

References:
* http://sethsec.blogspot.com/2014/03/exploiting-misconfigured-crossdomainxml.html
* http://gursevkalra.blogspot.com/2013/08/bypassing-same-origin-policy-with-flash.html
* https://www.adobe.com/devnet/articles/crossdomain_policy_file_spec.html
* https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/CrossDomain_PolicyFile_Specification.pdf
* https://www.owasp.org/index.php/Test_RIA_cross_domain_policy_%28OTG-CONFIG-008%29
]]

---
-- @usage nmap --script http-crossdomainxml <target>
-- @usage nmap -p80 --script http-crossdomainxml --script-args domain-lookup=true <target>
-- 
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack ttl 40
-- | http-crossdomainxml: 
-- |   VULNERABLE:
-- |   Cross-domain policy file (crossdomain.xml)
-- |     State: VULNERABLE
-- |       A cross-domain policy file specifies the permissions that a web client such as Java, Adobe Flash, Adobe Reader, 
-- |       etc. use to access data across different domains. Overly permissive configurations enables Cross-site Request 
-- |       Forgery attacks, and may allow third parties to access sensitive data meant for the user.
-- |     Check results:
-- |       <cross-domain-policy>
-- |       <allow-access-from domain="*.0xdeadbeefcafe.com"/>
-- |       <allow-access-from domain="*.0xdeadbeefcafe2.com"/>
-- |       </cross-domain-policy>
-- |       --------------
-- |       <?xml version="1.0" encoding="utf8"?>
-- |       <accesspolicy>
-- |         <crossdomainaccess>
-- |           <policy>
-- |             <allowfrom httprequestheaders="SOAPAction">
-- |               <domain uri="*"/>
-- |             </allowfrom>
-- |             <granto>
-- |               <resource path="/" includesubpaths="true"/>
-- |             </granto>
-- |           </policy>
-- |         </crossdomainaccess>
-- |       </accesspolicy>
-- |     Extra information:
-- |       Trusted domains:0xdeadbeefcafe2.com, 0xdeadbeefcafe.com, "*"
-- |   Use the script argument 'domain-lookup' to find trusted domains available for purchase
-- |     References:
-- |       https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/CrossDomain_PolicyFile_Specification.pdf
-- |       http://gursevkalra.blogspot.com/2013/08/bypassing-same-origin-policy-with-flash.html
-- |       https://www.adobe.com/devnet/articles/crossdomain_policy_file_spec.html
-- |       http://sethsec.blogspot.com/2014/03/exploiting-misconfigured-crossdomainxml.html
-- |_      https://www.owasp.org/index.php/Test_RIA_cross_domain_policy_%28OTG-CONFIG-008%29

-- 
-- @args http-crossdomainxml.domain-lookup Boolean to check domain availability. Default:false
---

author = {"Seth Art <sethsec()gmail>", "Paulino Calderon <calderon()websec.mx>", "Gyanendra Mishra"}
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "external", "vuln"}

portrule = shortport.http
local tlds_instantdomainsearch = {".com", ".net", ".org", ".co", ".info", ".biz", ".mobi", ".us", ".ca", ".co.uk",
                          ".in", ".io", ".it", ".pt", ".me", ".tv"}

---
-- Queries instantdomainsearch.com to check if domains are available
-- Returns nil if the query failed and true/false to indicate domain availability
--
-- Sample response:
--
-- {"label":"nmap","tld":"com","isRegistered":true,"isBid":false,
-- "price":0,"aftermarketProvider":"","rank":14.028985023498535,"search":"name"}
-- {"words":["nmap"],"synonyms":["nmap","scans"],"tld":"com","isBid":false,"price":0,
-- "aftermarketProvider":"","rank":0.23496590554714203,"search":"word"}
-- {"label":"snmap","tld":"com","isBid":false,"price":2994,"aftermarketProvider":"afternic.com",
-- "rank":9.352656364440918,"search":"ngram"}
---
local function check_domain (domain)
  local name, tld = domain:match("(%w*)%.*(%w*%.%w+)$")
  if not(stdnse.contains(tlds_instantdomainsearch, tld)) then
    stdnse.debug(1, "TLD '%s' is not supported by instantdomainsearch.com. Check manually.", tld)
    return nil
  end

  stdnse.print_debug(1, "Checking availability of domain %s with tld:%s ", name, tld)
  local path = string.format("/all/%s?/tlds=%s&limit=1", name, tld) 
  local response = http.get("instantdomainsearch.com", 443, path) 
  if ( not(response) or (response.status and response.status ~= 200) ) then 
    return nil 
  end 
  local _, _, registered = response.body:find('"isRegistered":(.-),"isBid":')
  return registered
end

---
-- Requests and parses crossdomain.xml file
---
function check_crossdomain(host, port, lookup)
  local trusted_domains = {}
  local trusted_domains_available = {}
  local content = {}
  local req_opt = {redirect_ok=function(host,port)
    local c = 3
    return function(url)
      if ( c==0 ) then return false end
      c = c - 1
      return true
    end
  end}
  local CROSSDOMAIN = {
    name = 'crossdomain',
    url = '/crossdomain.xml', 
    allow_access = '<allow%-access%-from(.-)%/>',
    wildcard_1 = 'domain%=\"(%*)\"',
    wildcard_2 = 'domain%=\"(https?://%*)\"',
    parse_domain = 'domain%=\"(.-)\"',
  }
  local CLIENTACCESS = {
    name = 'clientaccesspolicy',
    url = '/clientaccesspolicy.xml', 
    allow_access = '<(domain uri=".-")/>',
    wildcard_1 = 'domain uri%=\"(%*)\"',
    wildcard_2 = 'domain uri%=\"(https?://%*)\"',
    parse_domain = 'domain uri%=\"(.-)\"',
  }
  local lists = {}
  table.insert(lists, CROSSDOMAIN)
  table.insert(lists, CLIENTACCESS)
  for _, list in pairs(lists) do
    local req = http.get(host, port, list.url, req_opt)
    if req.status and req.status == 200 then
      table.insert(content, req.body)
      for line in req.body:gmatch(list.allow_access) do
        line = line:gsub("^%s*(.-)%s*$", "%1")
        --Matches wildcard, which means vulnerable as any host can comunicate with app
        if line:match(list.wildcard_1) or line:match(list.wildcard_2)  then
          stdnse.debug(1, "Wildcard detected!")
          table.insert(trusted_domains, line:match(list.wildcard_1) or line:match(list.wildcard_2))
        else
          --Parse domains
          line = line:match(list.parse_domain):gsub("%*%.", "")
          stdnse.debug(1, "Extracted line: %s", line)
          
          local domain  = line:match("(%w*%.*%w+%.%w+)$")
          if domain ~= nil then
            --Deals with tlds with double extension
            local tld = domain:match("%w*(%.%w*)%.%w+$") 
            if tld ~= nil and not(stdnse.contains(tlds_instantdomainsearch, tld)) then
              domain = domain:match("%w*%.(.*)$")
            end
            --We add domains only once as they can appear multiple times
            if not(stdnse.contains(trusted_domains, domain)) then
              stdnse.debug(1, "Added trusted domain:%s", domain)
              table.insert(trusted_domains, domain)
              --Lookup domains if script argument is set
              if ( lookup ) then
                if check_domain(domain) == "false" then
                  stdnse.debug(1, "Domain '%s' is available for purchase!", domain)
                  table.insert(trusted_domains_available, domain)
                end
              end
            
            end
          end
          stdnse.debug(1, "Extracted domain: %s", domain)     
        end
      end
    end
  end
  if (#trusted_domains> 0 or trusted_domains['clientaccesspolicy']> 0) then 
    return true, trusted_domains, trusted_domains_available, content 
  else 
    return nil 
  end  
end


action = function(host, port)
  local lookup = stdnse.get_script_args(SCRIPT_NAME..".domain-lookup") or false

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln = {
       title = 'Cross-domain policy file (crossdomain.xml)',
       state = vulns.STATE.NOT_VULN,
       description = [[
A cross-domain policy file specifies the permissions that a web client such as Java, Adobe Flash, Adobe Reader, 
etc. use to access data across different domains. Overly permissive configurations enables Cross-site Request 
Forgery attacks, and may allow third parties to access sensitive data meant for the user.]],
       references = {
          'http://sethsec.blogspot.com/2014/03/exploiting-misconfigured-crossdomainxml.html',
          'http://gursevkalra.blogspot.com/2013/08/bypassing-same-origin-policy-with-flash.html',
          'https://www.adobe.com/devnet/articles/crossdomain_policy_file_spec.html',
          'https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/CrossDomain_PolicyFile_Specification.pdf',
          'https://www.owasp.org/index.php/Test_RIA_cross_domain_policy_%28OTG-CONFIG-008%29'
       },
     }

  local check, domains, domains_available, content = check_crossdomain(host, port, lookup)

  if check then
    if stdnse.contains(domains, "*") or stdnse.contains(domains, "https://") or stdnse.contains(domains, "http://") then
      vuln.state = vulns.STATE.VULN
    else 
      vuln.state = vulns.STATE.LIKELY_VULN
    end
    vuln.check_results = stdnse.strjoin('\n--------------\n', content)
    vuln.extra_info = string.format("Trusted domains:%s\n", stdnse.strjoin(', ', domains))
    if not(lookup) and nmap.verbosity()>=2 then
      vuln.extra_info = vuln.extra_info .. "Use the script argument 'domain-lookup' to find trusted domains available for purchase"
    end
    if lookup ~= nil and #domains_available>0 then
      vuln.state = vulns.STATE.EXPLOIT
      vuln.extra_info = vuln.extra_info .. string.format("\n[!]Trusted domains available for purchase:%s",
                                                        stdnse.strjoin(', ', domains_available))                     
    end  

  end

  return vuln_report:make_output(vuln)
end
