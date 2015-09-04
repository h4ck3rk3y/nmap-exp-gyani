---
-- A library offering general-purpose canonicalization of
-- OS version strings and generation of CPE info.
-- The script uses the lookup table and if that fails it
-- tries to parse the version string itself.
-- Usage
-- local status, name, cpe = osinfo.get_os_info(version_string, hints)
-- @author Gyanendra Mishra
-- The OS Table comes from http://gaijin.at/en/lstwinver.php
-- https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
-- EXPERIMENTAL BUGGY VERSION. IF YOU WANT SOMETHING THAT WORKS PLEASE LOOK AT nmap-exp/gyani/nselib/osinfo.lua
--

local KEEP_TRYING = 1 -- this parse function couldn't lead to satisfactory result. switch to next.
local STOP_AND_SUCCEED = 2 -- this parse function lead to the best possible result. stop. and output.
local STOP_AND_FAIL = 3 -- no parse function could return anything. no point trying anymore. let's quit.
local GO_TO_NEXT_LEVEL = 4 -- this parse function resulted in something. but need to look deeper.

local stdnse = require 'stdnse'
local string = require 'string'
local table = require 'table'
local unittest = require "unittest"

_ENV = stdnse.module("osinfo", stdnse.seeall)

UTILITY = {

  --- A function to extract the version whatever that maybe
  -- @param version string
  get_version = function(version_string, look_at, hints)
    version_string = version_string:gsub("Windows (%d%.%d)", "")
    hints.osgeneration = (version_string:match "%s(%d+%.%d+)")
    if look_at[hints.osgeneration] then
      return GO_TO_NEXT_LEVEL, look_at[hints.osgeneration], hints
    else
      stdnse.debug("Added generation but the version is not in our version table: %s", hints.osgeneration)
      return KEEP_TRYING, look_at, hints
    end
  end,

  --- Can be used if the hint table doesn't specify the family of the os
  get_vendor = function(version_string, look_at, hints)
    if version_string:match "^Windows" or version_string:match "^CYGWIN" then
      hints.vendor = "Microsoft"
      return GO_TO_NEXT_LEVEL, look_at[hints.vendor], hints
    elseif version_string:match "^Linux" then
      hints.vendor = "Linux"
      return GO_TO_NEXT_LEVEL, look_at[hints.vendor], hints
    elseif version_string:match("^Darwin") then
      hints.vendor = "Apple"
      return GO_TO_NEXT_LEVEL, look_at[hints.vendor], hints
    elseif version_string:match("^GNU") then
      hints.vendor = "GNU"
      return GO_TO_NEXT_LEVEL, look_at[hints.vendor], hints
    elseif version_string:match("^DragonFly") then
      hints.vendor = "DragonFly"
      return GO_TO_NEXT_LEVEL, look_at[hints.vendor], hints
    elseif version_string:match("^SunOS") then
      hints.vendor = "Sun Microsystems"
      return GO_TO_NEXT_LEVEL, look_at[hints.vendor], hints
    end
    return KEEP_TRYING, look_at, hints
  end,

  --- Can be used if the hint table doesn't specify the family of the os
  get_family = function(version_string, look_at, hints)
    if version_string:match "^Windows" then
      hints.osfamily = "Windows"
      return GO_TO_NEXT_LEVEL, look_at[hints.osfamily], hints
    elseif version_string:match "^Linux" then
      hints.osfamily = "Linux"
      return GO_TO_NEXT_LEVEL, look_at[hints.osfamily], hints
    elseif version_string:match("^Darwin") then
      hints.osfamily = "Darwin"
      return GO_TO_NEXT_LEVEL, look_at[hints.osfamily], hints
    elseif version_string:match("^GNU.-Hurd") then
      hints.osfamily = "Hurd"
      return GO_TO_NEXT_LEVEL, look_at[hints.osfamily], hints
    elseif version_string:match("^DragonFly") then
      hints.osfamily = "DragonFly"
      return GO_TO_NEXT_LEVEL, look_at[hints.osfamily], hints
    elseif version_string:match("^SunOS") then
      hints.osfamily = "SunOS"
      return GO_TO_NEXT_LEVEL, look_at[hints.osfamily], hints
    end
    return KEEP_TRYING, look_at, hints
  end,

}


WINDOWS = {


  Editions = {
    "Home",
    "Professional",
    "Enterprise",
    "Ultimate",
    "Starter",
    "Pro",
    "RT",
  },


  -- Grabs the Type of Windows
  get_type = function (version_string)
    if not version_string:match "Server" then
      return "client"
    else
      return "server"
    end
  end,

  --- A function to grab the service pack version
  get_update = function (version_string)
    if version_string:match "Service Pack %d+" then
      return "sp", version_string:match "Service Pack (%d+)"
    elseif version_string:match "Service Release %d+" then
      return "sr", version_string:match "Service Pack (%d+)"
    end
    return false, false
  end,

  --- A function to extract the build version from string
  -- most windows build versions are four digit
  get_build = function(version_string)
    if not version_string:match "Server" then
      return version_string:match "%d%d%d%d?%d?"
    else
      -- Let us remove the Year
      version_string = version_string:gsub("Server .- (%d%d%d%d)", "")
      return version_string:match "%d%d%d%d?%d?"
    end
  end,


  --- Does a structured look up of the windows table
  -- @param version string the version string as grabbed from banner
  -- @param version
  -- @return status A boolean, true or false.
  -- @return name The name of the OS. A generic name is returned if no build number is specified.
  -- @return cpe returns cpe information particular to the os.
  -- @see get_all_cpe to get all cpe information for a particualr version
  parse  =  function (version_string, look_at, hints)

    local build = WINDOWS.get_build(version_string)
    local win_type = WINDOWS.get_type(version_string)
    local version = hints and hints.osgeneration or UTILITY.get_version(version_string)

    if not version then
      stdnse.debug2("Couldn't Parse Version information")
      return STOP_AND_FAIL, look_at, hints
    end

    local status, name, cpe, _

    if not build or not look_at[build] then
      name = look_at.name
    else
      -- Suppose client type os is requested but doesn't exist then return general name for version number
      if not look_at[build][win_type] then
        name = look_at.name
      else
        name = look_at[build][win_type].name
        cpe = look_at[build][win_type].cpe
      end
    end

    local cpe_obj, parts = CPE:new(version_string, nil , cpe)
    if cpe then
      status, _, parts = cpe_obj:decode()
      if status then
        cpe_obj.cpe_table = parts
      end
      cpe_obj.cpe_string = nil
    end
    status, cpe = cpe_obj:make_cpe()
    if not status then
      cpe = "Unknown"
    end

    -- check if there is an edition match
    for _, edition in pairs(WINDOWS.Editions) do
      if version_string:match(edition) then
        name = name .. " " .. edition
        break
      end
    end

    hints = hints or {}
    hints.name = name
    hints.cpe = cpe

    return STOP_AND_SUCCEED, look_at, hints
  end,

}

UNAME = {

  parse  = function(uname_string, look_at, hints, pat)

    local _
    local u = {}
    local cpe = ""
    local name = ""

    u.kernel_name = uname_string:sub(1, uname_string:find("%s") -1)
    u.node_name, u.kernel_release, u.kernel_verson, u.machine, u.processor,
    u.hardware_platform = uname_string:match(pat)
    if u.kernel_name == "Linux" then
      u.os = "GNU/Linux"
      cpe = "cpe:/:o:linux:linux_kernel:" .. u.kernel_release:match("%d*%.%d*%.%d*")
      name = "Linux " .. u.kernel_release:match("%d*%.%d*%.%d*")
    elseif u.kernel_name == "Darwin" then
      u.os = "Mac"
      cpe = "cpe:/o:apple:darwin" .. u.kernel_verison
      name = "Mac OS" .. u.kernel_verison
    elseif u.kernel_name:find("CYGWIN") then
      u.os = "Windows" .. hints.osgeneration
      name = hints.name or u.os -- get_version might return a better name/cpe combo :)
      cpe = hints.cpe or "cpe:/o:microsoft:windows_nt_" .. hints.osgeneration
    elseif u.kernel_name == "GNU" then
      u.os = "GNU"
      name = "GNU"
      cpe = "cpe:/o:gnu:gnu_hurd:" .. u.kernel_release
    elseif u.kernel_name == "DragonFly" then
      u.os = "DragonFlyBSD"
      name = u.os
      cpe = "cpe:/o:dragonfly:dragonflybsd"
    elseif u.kernel_name == "SunOS" then
      u.os = "Solaris"
      name = u.os
      cpe = "cpe:/o:sun_microsystems:solaris"
    else
      return KEEP_TRYING, look_at, hints
    end

    hints.name = name
    hints.cpe = cpe
    hints.uname = u

    return STOP_AND_SUCCEED, look_at, hints

  end,

}

CPE = {

  Parts = {
      "part",
      "vendor",
      "product",
      "version",
      "update",
      "edition",
      "language"
  },

  new = function(self, version_string, cpe_table, cpe_string)
    local o  = {}
    o.version_string = version_string or ""
    o.cpe_table = cpe_table or {}
    o.cpe_string = cpe_string or ""
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- this function can be over ridden by passing a cpe_table along with a version string.
  -- in this case it adds to the existing cpe_table. The cpe table in this case is
  -- the one with numeric keys.
  make_cpe = function(self)

    local parts = {}
    if self.cpe_table and #self.cpe_table > 0 then
      parts = self.cpe_table
    elseif string.match(self.version_string, "^Windows 5%.0") or string.match(self.version_string, "^Windows 2000") then
      parts = {"o", "microsoft", "windows_2000"}
    elseif string.match(self.version_string, "^Windows 5%.1") or string.match(self.version_string, "^Windows XP") then
      parts = {"o", "microsoft", "windows_xp"}
    elseif string.match(self.version_string, "^Windows Server.*2003") then
      parts = {"o", "microsoft", "windows_server_2003"}
    elseif string.match(self.version_string, "^Windows Vista") then
      parts = {"o", "microsoft", "windows_vista"}
    elseif string.match(self.version_string, "^Windows Server.*2008") then
      parts = {"o", "microsoft", "windows_server_2008"}
    elseif string.match(self.version_string, "^Windows 7") then
      parts = {"o", "microsoft", "windows_7"}
    elseif string.match(self.version_string, "^Windows 8%f[^%d.]") then
      parts = {"o", "microsoft", "windows_8"}
    elseif string.match(self.version_string, "^Windows 8.1") then
      parts = {"o", "microsoft", "windows_8.1",}
    elseif string.match(self.version_string, "^Windows 10%f[^%d.]") then
      parts = {"o", "microsoft", "windows_10"}
    elseif string.match(self.version_string, "^Windows Server.*2012") then
      parts = {"o", "microsoft", "windows_server_2012"}
    else
      return false
    end

    if parts[1] == "o" and parts[2] == "microsoft" and string.match(parts[3], "^windows") then
      local update_type, update_version = WINDOWS.get_update(self.version_string)
      if update_type then
        parts[4] = ""
        parts[5] = update_type .. update_version
      end
      for _, edition in pairs(WINDOWS.Editions) do
        if self.version_string:match(edition) then
          parts[4] = ""
          parts[5] = ""
          parts[6] = edition:lower()
          break
        end
      end
    end

    self.cpe_table = parts
    return self:encode()

  end,

  decode = function(self)
    self.cpe_string = self.cpe_string or self.version_string and self:make_cpe() or ""

    local cpe, numeric_keys = {}

    numeric_keys = stdnse.strsplit(":", self.cpe_string:sub(6))

    for i, part in ipairs(numeric_keys) do
      cpe[CPE.Parts[i]] = part
    end

    if next(cpe) then return true, cpe, numeric_keys else return false end

  end,

  encode = function(self)

    if self.cpe_table and #self.cpe_table > 0 then
       return true, "cpe:/" .. stdnse.strjoin(":", self.cpe_table)
    elseif self.cpe_table and next(self.cpe_table) then

      local parts = {}
      for _, part in ipairs(CPE.Parts) do
        if self.cpe_table[part] then
          table.insert(parts, self.cpe_table[part])
        else
          table.insert(parts, "")
        end
      end

      return true, "cpe:/" .. stdnse.strjoin(":", parts)

    else
      return false
    end

  end

}

local db = {
  ["Microsoft"] = {
    ["Windows"] = {
        ["3.10"] = {
        name = "Windows NT 3.1",
        ["528"] = {
          client = {
            name = "Windows NT 3.1",
            cpe = "cpe:/o:microsoft:windows_nt_3.1",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["3.50"] = {
        name = "Windows NT 3.50",
        ["807"] = {
          client = {
            name = "Windows NT 3.50",
            cpe = "cpe:/o:microsoft:windows_nt_3.50",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["3.51"] = {
        name = "Windows NT 3.51",
        ["1057"] = {
          client = {
            name = "Windows NT 3.51",
            cpe = "cpe:/o:microsoft:windows_nt_3.51",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["4.00"] = {
        name = "Windows 95 or Windows NT 4.00",
        ["950"] = {
          client = {
            name = "Windows 95 OEM Service Release 1",
            cpe = "cpe:/o:microsoft:windows_95::sr1",
          },
        },
        ["1111"] = {
          client = {
            name = "Windows 95 OEM Service Release 2",
            cpe = "cpe:/o:microsoft:windows_95::sr2",
          },
        },
        ["1381"] = {
          client = {
            name = "Windows NT 4.00",
            cpe = "cpe:/o:microsoft:windows_nt_4.00",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["4.03"] = {
        ["1212"] = {
          client = {
            name = "Windows 95 OEM Service Release 2.1",
            cpe = "cpe:/o:microsoft:windows_95::sr2.1",
          },
        },
        ["1213"] = {
          client = {
            name = "Windows 95 OEM Service Release 2.1",
            cpe = "cpe:/o:microsoft:windows_95::sr2.1",
          },
        },
        ["1214"] = {
          client = {
            name = "Windows 95 OEM Service Release 2.1",
            cpe = "cpe:/o:microsoft:windows_95::sr2.1",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["4.10"] = {
        ["1998"] = {
          client = {
            name = "Windows 98",
            cpe = "cpe:/o:microsoft:windows_98",
          },
        },
        ["2222"] = {
          client = {
            name = "Windows 98",
            cpe = "cpe:/o:microsoft:windows_98::se",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["4.90"] = {
        ["2476"] = {
          client = {
            name = "Windows Milenium Beta",
            cpe = "cpe:/o:microsoft:windows_milenium::beta",
          },
        },
        ["3000"] = {
          client = {
            name = "Windows Milenium Beta",
            cpe = "cpe:/o:microsoft:windows_milenium",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["5.0"] = {
        name = "Windows 2000",
        ["1515"] = {
          client = {
            name = "Windows NT 5.0",
            cpe = "cpe:/o:microsoft:windows_nt_5.0::beta2",
          },
        },
        ["2031"] = {
          client = {
            name = "Windows 2000",
            cpe = "cpe:/o:microsoft:windows2000::beta3",
          },
        },
        ["2128"] = {
          client = {
            name = "Windows 2000",
            cpe = "cpe:/o:microsoft:windows2000::beta3",
          },
        },
        ["2183"] = {
          client = {
            name = "Windows 2000",
            cpe = "cpe:/o:microsoft:windows2000::beta3",
          },
        },
        ["2195"] = {
          client = {
            name = "Windows 2000",
            cpe = "cpe:/o:microsoft:windows2000",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["5.1"] = {
        name = "Windows XP",
        ["2505"] = {
          client = {
            name = "Windows XP",
            cpe = "cpe:/o:microsoft:windows_xp::rc1",
          },
        },
        ["2600"] = {
          client = {
            name = "Windows XP",
            cpe = "cpe:/o:microsoft:windows_xp",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["5.2"] = {
        name = "Windows Server 2003",
        ["3718"] = {
          server = {
            name = "Windows .NET Server 2003",
            cpe = "cpe:/o:microsoft:windows_.net_server_2003::rc2",
          },
        },
        ["3763"] = {
          server = {
            name = "Windows Server 2003",
            cpe = "cpe:/o:microsoft:windows_server_2003::beta",
          },
        },
        ["3790"] = {
          server = {
            name = "Windows Server 2003",
            cpe = "cpe:/o:microsoft:windows_server_2003",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["6.0"] = {
        name = "Windows Vista or Server 2008",
        ["6002"] = {
          client = {
            name = "Windows Vista SP2",
            cpe = "cpe:/o:microsoft:windows_vista::sp2",
          },
        },
        ["6001"] = {
          server = {
            name = "Windows Server 2008",
            cpe = "cpe:/o:microsoft:windows_server_2008",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["6.1"] = {
        name = "Windows 7 or Windows Server 2008 R2 or Windows Home Server 2011",
        ["7600"] = {
          client = {
            name = "Windows 7",
            cpe = "cpe:/o:microsoft:windows_7::rtm",
          },
          server = {
            name = "Windows Server 2008 R2",
            cpe = "cpe:/o:microsoft:windows_server_2008_r2::rtm",
          },
        },
        ["7601"] = {
          client = {
            name = "Windows 7",
            cpe = "cpe:/o:microsoft:windows_7",
          },
          server = {
            name = "Windows 2008, R2 SP1",
            cpe = "cpe:/o:microsoft:windows_server_2008_r2::sp1",
          },
        },
        ["8400"] = {
          server = {
            name = "Windows Home Server 2011",
            cpe = "cpe:/o:microsoft:windows_home_server_2011",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["6.2"] = {
        name = "Windows 8 or Windows Server 2012 or Windows Phone 8",
        ["9200"] = {
          client = {
            name = "Windows 8",
            cpe = "cpe:/o:microsoft:windows_8",
          },
          server = {
            name = "Windows Server 2012",
            cpe = "cpe:/o:microsoft:windows_server_2012",
          },
        },
        ["10211"] = {
          client = {
            name = "Windows Phone 8",
            cpe = "cpe:/o:microsoft:windows_phone_8",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["6.3"] = {
        name = "Windows 8.1 or Windows Server 2012 or maybe Win 10",
        ["9200"] = {
          client = {
            name = "Windows 8.1",
            cpe = "cpe:/o:microsoft:windows_8.1",
          },
          server = {
            name = "Windows Server 2012",
            cpe = "cpe:/o:microsoft:windows_server_2012_r2",
          },
        },
        ["9600"] = {
          client = {
            name = "Windows 8.1 Update 1",
            cpe = "cpe:/o:microsoft:windows_8.1",
          },
        },
        ["10240"] = {
          client = {
            name = "Windows 10",
            cpe = "cpe:/o:microsoft:windows_10"
          }
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["6.4"] = {
        name = "Windows 10",
        ["9879"] = {
          client = {
            name = "Windows 10",
            cpe = "cpe:/o:microsoft:windows_10.0",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      ["10.0"] = {
        name = "Windows 10",
        ["9888"] = {
          client = {
            name = "Windows 10",
            cpe = "cpe:/o:microsoft:windows_10.0",
          },
        },
        {func = WINDOWS.parse, pat = nil},
      },
      {func = UTILITY.get_version, pat = nil},
      {func = UNAME.parse, pat = "CYGWIN_NT-[0-9%.%-A-Z]* (.-) (%d%.%d%.%d*%(%d%.%d*%/%d%/%d%)) (%d%d%d%d%-%d%d%-%d%d %d%d:%d%d) ([a-zA-Z0-9%_]*) Cygwin"},
    },
    {func = UTILITY.get_family, pat = nil}
  },
  ["Linux"] = { ["Linux"] = {func = UNAME.parse, pat = "Linux (.-) ([0-9%.%-a-z]*) (#[%d%.-a-z~A-Z]* %w%s*%w* %w%w%w %w* %d* %d*:%d*:%d* %w* %d*) ([a-zA-Z0-9%_]*) ([a-zA-Z0-9%_]*) ([a-zA-Z0-9%_]*) GNU/Linux"}},
  ["Apple"] = {["Darwin"] = {func = UNAME.parse, pat = "Darwin (.-) (%d*%.%d*%.%d*) (Darwin Kernel Version %d*%.%d*%.%d*: %w%w%w %w%w%w %d%d? %d%d:%d%d:%d%d %w%w%w %d%d%d%d; root:xnu[%-%/a-zA-Z0-9%.%_]*) ([a-zA-Z0-9%s]*)"}},
  ["GNU"] = {["Hurd"] = {func = UNAME.parse, pat = "GNU (.-) (%d%.%d) GNU-Mach %d%.%d%.%d*%-%d*%/Hurd%-%d%.%d ([a-zA-Z0-9%_]*) GNU"}},
  ["DragonFly"] = {["DragonFly"] = {func = UNAME.parse, pat = "DragonFly (.-) ([0-9%.%-a-z]*) (DragonFly v%d*%.%d*%.%d*%.%d*[a-zA-Z0-9%.]* #%d*: %w%w%w %w%w%w %d%d? %d%d:%d%d:%d%d %w%w%w %d%d%d%d .-) ([a-zA-Z0-9])*"}},
  ["Sun Microsystems"] = {["SunOS"] = {func = UNAME.parse, pat = "SunOS (.-) (%d+%.%d+) ([a-zA-Z0-9%-%_]*) ([a-z0-9]*) ([a-z0-9]*) ([a-zA-Z0-9%,%-])*"}},
  {func = UTILITY.get_vendor, pat = nil}
}

function get_os_info(version_string, hints)
  local look_at = db
  local signal = KEEP_TRYING
  hints = hints or {}
  for i, level in ipairs({"vendor", "osfamily", "osgeneration", "unamed_4th_level"}) do
    if hints[level] and look_at[hints[level]] then
      look_at = look_at[hints[level]]
    else -- inadequate hints or hints sent us down the wrong path.
      for _, parser in ipairs(look_at) do
        signal, look_at, hints = parser.func(version_string, look_at, hints, parser.pat)
        if signal ~= KEEP_TRYING then -- this level returned one of stop_and_succeed, stop_and_fail or go_to_next_level
          break
        end
      end
      if signal ~= GO_TO_NEXT_LEVEL then -- no more levels can be reached
        break
      end
    end
  end
  if signal == STOP_AND_SUCCEED then
    return true, hints.name, hints.cpe, hints
  else
    return false, hints
  end
end

if not unittest.testing() then
  return _ENV;
end

test_suite = unittest.TestSuite:new()
local equal = unittest.equal

local tests = {
  {"Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)", "Windows Server 2008", "cpe:/o:microsoft:windows_server_2008::sp1"},
  {"Windows Server 2003 5.2 (Build 3790: Service Pack 2)", "Windows Server 2003", "cpe:/o:microsoft:windows_server_2003::sp2"},
  {"Windows 2000 Service Pack 4 (ServerNT 5.0 build 2195)", "Windows 2000", "cpe:/o:microsoft:windows_2000::sp4"},
  {"Windows 7 (Build 7601 6.1)", "Windows 7", "cpe:/o:microsoft:windows_7"},
  {"Windows 8 Service Pack 2 Pro (Build 9200 6.2)", "Windows 8 Pro", "cpe:/o:microsoft:windows_8:::pro"},
  {"Windows 10 Pro 10240 (Windows 10 Pro 6.3)", "Windows 10 Pro", "cpe:/o:microsoft:windows_10:::pro"},
  {"Windows 8 Single Language 9200 (Windows 8 Single Language 6.2)", "Windows 8", "cpe:/o:microsoft:windows_8"},
  {"Windows 8.1 Single Language 9600 (Windows 8.1 Single Language 6.3)", "Windows 8.1 Update 1", "cpe:/o:microsoft:windows_8.1"}
}

for _, test in pairs(tests) do
  local status, name, cpe = get_os_info(test[1])
  test_suite:add_test(equal(test[2], name), "Name")
  test_suite:add_test(equal(test[3], cpe), "CPE")
end

return _ENV;