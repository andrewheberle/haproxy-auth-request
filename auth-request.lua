-- The MIT License (MIT)
--
-- Copyright (c) 2018 Tim Düsterhus
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.

local http = require("socket.http")
local JSON = require("JSON")
local ltn12 = require("ltn12")

-- map containing json keys to variables
local json_map = Map.new("/etc/haproxy/maps/auth-request.map", Map._str)
-- map containing variables to headers
local header_map = Map.new("/etc/haproxy/maps/auth-request_headers.map", Map._str)

core.register_action("auth-request_set_header", { "http-req" }, function(txn, hdr)
	local v = header_map:lookup(hdr)
	-- ensure header is deleted
	txn.http:req_del_header(hdr)
	if v ~= nil then
		local value = txn:get_var(v)
		if value ~= nil then
			-- set header
			txn.http:req_set_header(hdr, value)
		else
			-- variable not set
			txn:Info("Variable '" .. v .. "' not set")
		end
	else
		-- not found in map
		txn:Info("Mapping for '" .. hdr .. "' not found")
	end
end, 1)

core.register_action("auth-request", { "http-req" }, function(txn, be, path)
	txn:set_var("txn.auth_response_successful", false)

	-- Check whether the given backend exists.
	if core.backends[be] == nil then
		txn:Alert("Unknown auth-request backend '" .. be .. "'")
		txn:set_var("txn.auth_response_code", 500)
		return
	end

	-- Check whether the given backend has servers that
	-- are not `DOWN`.
	local addr = nil
	for name, server in pairs(core.backends[be].servers) do
		local status = server:get_stats()['status']
		if status == "no check" or status:find("UP") == 1 then
			addr = server:get_addr()
			break
		end
	end
	if addr == nil then
		txn:Warning("No servers available for auth-request backend: '" .. be .. "'")
		txn:set_var("txn.auth_response_code", 500)
		return
	end

	-- Transform table of request headers from haproxy's to
	-- socket.http's format.
	local headers = {}
	for header, values in pairs(txn.http:req_get_headers()) do
		if header ~= 'content-length' then
			for i, v in pairs(values) do
				if headers[header] == nil then
					headers[header] = v
				else
					headers[header] = headers[header] .. ", " .. v
				end
			end
		end
	end

	local t = {}

	-- Make request to backend.
	local b, c, h = http.request {
		url = "http://" .. addr .. path,
		headers = headers,
		create = core.tcp,
		sink = ltn12.sink.table(t),
		-- Disable redirects, because DNS does not work here.
		redirect = false
	}

	-- Check whether we received a valid HTTP response.
	if b == nil then
		txn:Warning("Failure in auth-request backend '" .. be .. "': " .. c)
		txn:set_var("txn.auth_response_code", 500)
		return
	end

	-- 2xx: Allow request.
	if 200 <= c and c < 300 then
		txn:set_var("txn.auth_response_successful", true)
		txn:set_var("txn.auth_response_code", c)
		-- if we got a JSON response, decode it
		if h["content-type"] == "application/json" then
			local json_string = table.concat(t)
			local json = JSON:decode(json_string)
			if json ~= nil then
				-- Based on data in the loaded map (if any), set variables
				for key,value in pairs(json.data) do
					local v = json_map:lookup(key)
					if v ~= nil then
						txn:set_var(v, value[1])
					end
				end
			end
		end
	-- 401 / 403: Do not allow request.
	elseif c == 401 or c == 403 then
		txn:set_var("txn.auth_response_code", c)
	-- Everything else: Do not allow request and log.
	else
		txn:Warning("Invalid status code in auth-request backend '" .. be .. "': " .. c)
		txn:set_var("txn.auth_response_code", c)
	end
end, 2)
