local ok_http, http = pcall(require, "resty.http")
local ipinsubnet_module = require "resty.arxignis.ipinsubnet"
local ipinsubnet = ipinsubnet_module:new()

local utils = {_TYPE='module', _NAME='arxignis.utils', _VERSION='1.0-0'}

utils.HTTP_CODE = {}
utils.HTTP_CODE["200"] = ngx.HTTP_OK
utils.HTTP_CODE["202"] = ngx.HTTP_ACCEPTED
utils.HTTP_CODE["204"] = ngx.HTTP_NO_CONTENT
utils.HTTP_CODE["301"] = ngx.HTTP_MOVED_PERMANENTLY
utils.HTTP_CODE["302"] = ngx.HTTP_MOVED_TEMPORARILY
utils.HTTP_CODE["400"] = ngx.HTTP_BAD_REQUEST
utils.HTTP_CODE["401"] = ngx.HTTP_UNAUTHORIZED
utils.HTTP_CODE["401"] = ngx.HTTP_UNAUTHORIZED
utils.HTTP_CODE["403"] = ngx.HTTP_FORBIDDEN
utils.HTTP_CODE["404"] = ngx.HTTP_NOT_FOUND
utils.HTTP_CODE["405"] = ngx.HTTP_NOT_ALLOWED
utils.HTTP_CODE["406"] = ngx.HTTP_NOT_ACCEPTABLE
utils.HTTP_CODE["444"] = ngx.HTTP_CLOSE
utils.HTTP_CODE["500"] = ngx.HTTP_INTERNAL_SERVER_ERROR

utils.http_status_codes = {
  [200] = ngx.HTTP_OK,
  [202] = ngx.HTTP_ACCEPTED,
  [204] = ngx.HTTP_NO_CONTENT,
  [301] = ngx.HTTP_MOVED_PERMANENTLY,
  [302] = ngx.HTTP_MOVED_TEMPORARILY,
  [400] = ngx.HTTP_BAD_REQUEST,
  [401] = ngx.HTTP_UNAUTHORIZED,
  [403] = ngx.HTTP_FORBIDDEN,
  [404] = ngx.HTTP_NOT_FOUND,
  [405] = ngx.HTTP_NOT_ALLOWED,
  [406] = ngx.HTTP_NOT_ACCEPTABLE,
  [444] = ngx.HTTP_CLOSE,
  [500] = ngx.HTTP_INTERNAL_SERVER_ERROR,
}


function utils.read_file(path)
   local file = io.open(path, "r") -- r read mode and b binary mode
   if not file then return nil end
   io.input(file)
   local content = io.read("*a")
   io.close(file)
   return content:sub(1,-2)
 end

function utils.file_exist(path)
 if path == nil then
   return nil
 end
 local f = io.open(path, "r")
 if f ~= nil then
   io.close(f)
   return true
 else
   return false
 end
end

function utils.starts_with(str, start)
    return str:sub(1, #start) == start
 end

 function utils.ends_with(str, ending)
    return ending == "" or str:sub(-#ending) == ending
 end

function utils.table_len(table)
   local count = 0
   for k, v in pairs(table) do
      count = count + 1
   end
   return count
end

-- Generic HTTP client function
function utils.http_request(url, options)
  -- If resty.http is available, use it
  if ok_http and http and http.new then
    local httpc = http.new()

    -- Set timeout (default 30 seconds)
    local timeout = options.timeout or 30000
    httpc:set_timeout(timeout)

    -- Prepare headers
    local headers = options.headers or {}
    if not headers['Connection'] then
      headers['Connection'] = 'close'
    end
    if not headers['User-Agent'] then
      headers['User-Agent'] = 'Arxignis/1.0'
    end

    -- Prepare request options
    local request_opts = {
      method = options.method or 'GET',
      headers = headers,
      ssl_verify = options.ssl_verify ~= false -- default to true
    }

    -- Add body if provided
    if options.body then
      request_opts.body = options.body
    end

    -- Make the request
    local res, err = httpc:request_uri(url, request_opts)

    -- Close connection
    httpc:close()

    return res, err
  end

  -- Fallback simple HTTP client using cosocket (HTTP only)
  local parsed = {}
  do
    -- Only support http://host[:port]/path[?query]
    local scheme, host, port, path = string.match(url, "^(https?)://([^/:]+):?(%d*)(/.*)$")
    if not scheme or scheme ~= "http" then
      return nil, "unsupported_url_scheme"
    end
    parsed.host = host
    parsed.port = tonumber(port) or 80
    parsed.path = path ~= "" and path or "/"
  end

  local sock = ngx.socket.tcp()
  sock:settimeout(options.timeout or 30000)
  local ok, err = sock:connect(parsed.host, parsed.port)
  if not ok then
    return nil, err or "connect_failed"
  end

  local method = options.method or 'GET'
  local headers = options.headers or {}
  local body = options.body or nil

  if not headers['Host'] then headers['Host'] = parsed.host end
  if not headers['User-Agent'] then headers['User-Agent'] = 'Arxignis/1.0' end
  if not headers['Connection'] then headers['Connection'] = 'close' end
  if body and not headers['Content-Length'] then headers['Content-Length'] = tostring(#body) end

  local req_lines = { string.format("%s %s HTTP/1.1", method, parsed.path) }
  for k, v in pairs(headers) do
    table.insert(req_lines, string.format("%s: %s", k, v))
  end
  table.insert(req_lines, "")
  table.insert(req_lines, body or "")

  local bytes, send_err = sock:send(table.concat(req_lines, "\r\n"))
  if not bytes then
    sock:close()
    return nil, send_err or "send_failed"
  end

  local chunks = {}
  while true do
    local data, recv_err, partial = sock:receive(8192)
    if data then
      table.insert(chunks, data)
    elseif partial and #partial > 0 then
      table.insert(chunks, partial)
    end
    if recv_err == "closed" then
      break
    elseif recv_err then
      sock:close()
      return nil, recv_err
    end
  end
  sock:close()

  local raw = table.concat(chunks)
  local header_body_sep = string.find(raw, "\r\n\r\n", 1, true)
  if not header_body_sep then
    return nil, "invalid_http_response"
  end
  local header_str = string.sub(raw, 1, header_body_sep - 1)
  local body_str = string.sub(raw, header_body_sep + 4)

  local status_line_end = string.find(header_str, "\r\n", 1, true) or (#header_str + 1)
  local status_line = string.sub(header_str, 1, status_line_end - 1)
  local _, _, code = string.find(status_line, "HTTP/%d%.%d (%d%d%d)")
  local status = tonumber(code) or 0

  return { status = status, body = body_str, headers = {} }, nil
end

function utils.get_remediation_http_request(url, timeout, api_key, ssl_verify)
  local headers = {}

  -- Only add Authorization header if api_key is provided
  if api_key and api_key ~= "" then
    headers['Authorization'] = 'Bearer ' .. api_key
  end

  return utils.http_request(url, {
    method = 'GET',
    timeout = timeout,
    headers = headers,
    ssl_verify = ssl_verify
  })
end

function utils.post_remediation_http_request(url, timeout, api_key, ssl_verify, body)
  local headers = {}

  -- Only add Authorization header if api_key is provided
  if api_key and api_key ~= "" then
    headers['Authorization'] = 'Bearer ' .. api_key
  end

  -- Add Content-Type header for JSON
  headers['Content-Type'] = 'application/json'

  return utils.http_request(url, {
    method = 'POST',
    timeout = timeout,
    headers = headers,
    ssl_verify = ssl_verify,
    body = body
  })
end

function utils.get_http_request(url, timeout, api_key, ssl_verify)
  local headers = {}

  -- Only add Authorization header if api_key is provided
  if api_key and api_key ~= "" then
    headers['Authorization'] = 'Bearer ' .. api_key
  end

  return utils.http_request(url, {
    method = 'GET',
    timeout = timeout,
    headers = headers,
    ssl_verify = ssl_verify
  })
end

-- Check if IP is within a CIDR range
function utils.is_ip_in_cidr(ip, cidr)
  ipinsubnet:addSubnet(cidr)
  return ipinsubnet:isInSubnetsStrict(ip)
end

function utils.split_on_delimiter(str, delimiter)
  if str == nil then
    return nil
  end

  ngx.log(ngx.DEBUG, "split_on_delimiter: " .. str .. " using delimiter: " .. delimiter)

  local result = {}
  local pattern = "([^" .. delimiter .. "]+)"  -- Create a pattern to match between delimiters

  for word in string.gmatch(str, pattern) do
    table.insert(result, word)  -- Insert the split parts into the result table
  end

  return result  -- Return the split parts as a table
end

--- Convert a labels key, value table to a string.
--- @param t table to convert.
--- @return table ordered table
function utils.table_to_string(t)
    local sorted_keys = {}

    -- Collect all keys and sort them
    for key in pairs(t) do
      table.insert(sorted_keys, key)
    end
    table.sort(sorted_keys)

    -- Build an ordered version of the table
    local ret = ""
    for  _, key in pairs(sorted_keys) do
      ret = ret .. key .. "=" .. t[key] .. "&"
      ngx.log(ngx.DEBUG, "label key=value:" .. key .. "=" .. t[key])
    end

    -- Convert ordered table to JSON string
    return ret
end

--- Convert a string to a labels key, value table.
--- @param str string to convert.
--- @return table ordered table
function utils.string_to_table(str)
  local t = {}
  if str == nil then
    return {}
  end
  local labels_string = utils.split_on_delimiter(str, "&")
  if labels_string == nil then
    return {}
  end
  for _, v in pairs(labels_string) do
    ngx.log(ngx.DEBUG, "dealing with:" .. v)
    local label = utils.split_on_delimiter(v, "=")
    if label ~= nil and  #label == 2 then
      t[label[1]] = label[2]
    end
  end
  return t
end

-- Common functions for log and metrics modules

-- Helper function to safely get string values
function utils.safe_string(value)
    if value == nil then
        return ''
    end
    return tostring(value)
end



-- Get host name
function utils.get_host_name()
    return ngx.var.host or "unknown"
end

-- Get SSL variables
function utils.get_ssl_vars()
    return {
        ssl_protocol = ngx.var.ssl_protocol,
        http_ssl_cipher = ngx.var.http_ssl_cipher,
        http_ssl_ja4 = ngx.var.http_ssl_ja4,
        http_ssl_ja4_string = ngx.var.http_ssl_ja4_string,
        http_ssl_ja4one = ngx.var.http_ssl_ja4one,
        http_ssl_ja4s = ngx.var.http_ssl_ja4s,
        http_ssl_ja4s_string = ngx.var.http_ssl_ja4s_string,
        http_ssl_ja4h = ngx.var.http_ssl_ja4h,
        http_ssl_ja4h_string = ngx.var.http_ssl_ja4h_string,
        http_ssl_ja4t = ngx.var.http_ssl_ja4t,
        http_ssl_ja4t_string = ngx.var.http_ssl_ja4t_string,
        http_ssl_ja4ts = ngx.var.http_ssl_ja4ts,
        http_ssl_ja4ts_string = ngx.var.http_ssl_ja4ts_string,
        http_ssl_ja4x = ngx.var.http_ssl_ja4x,
        http_ssl_ja4l = ngx.var.http_ssl_ja4l
    }
end

-- Get request headers
function utils.get_request_headers()
    local headers = {}
    local header_names = ngx.req.get_headers()
    for name, value in pairs(header_names) do
        if type(value) == "table" then
            headers[name] = table.concat(value, ", ")
        else
            headers[name] = value
        end
    end
    return headers
end

-- Generate ISO timestamp
function utils.get_iso_timestamp()
    return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

return utils

