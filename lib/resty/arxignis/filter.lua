local cjson = require "cjson.safe"
local resty_string = require "resty.string"
local utils = require "resty.arxignis.utils"

local ngx = ngx
local type = type
local pairs = pairs
local tostring = tostring
local tonumber = tonumber
local setmetatable = setmetatable
local table_concat = table.concat
local io_open = io.open

local DEFAULT_BASE_URL = "https://api.arxignis.com"
local DEFAULT_TIMEOUT = 2000
local DEFAULT_EVENT_TYPE = "filter"
local DEFAULT_SCHEMA_VERSION = "1.0"
local FILTER_PATH = "/filter"

local filter = {_TYPE = "module", _NAME = "arxignis.filter", _VERSION = "1.0.0"}
filter.__index = filter

local function sanitize_base_url(url)
    local sanitized = url or DEFAULT_BASE_URL
    sanitized = sanitized:gsub('/+$', '')
    if sanitized == '' then sanitized = DEFAULT_BASE_URL end
    return sanitized
end

local function encode_args(args)
    if ngx and ngx.encode_args then return ngx.encode_args(args) end

    local parts = {}
    for key, value in pairs(args) do
        parts[#parts + 1] = tostring(key) .. "=" .. tostring(value)
    end
    return table_concat(parts, "&")
end

local function compute_sha256(value)
    if not value or value == "" then return nil end

    if ngx and ngx.sha256_bin and resty_string and resty_string.to_hex then
        local digest = ngx.sha256_bin(value)
        return resty_string.to_hex(digest)
    end

    return nil
end

local function read_request_body()
    if not ngx or not ngx.req then return nil end

    local ok, err = pcall(function() ngx.req.read_body() end)
    if not ok then
        if ngx.log then
            ngx.log(ngx.WARN, "Arxignis filter: failed to read request body: ",
                    tostring(err))
        end
        return nil
    end

    local data = ngx.req.get_body_data()
    if data then return data end

    local file_path = ngx.req.get_body_file and ngx.req.get_body_file()
    if not file_path then return nil end

    local file, open_err = io_open(file_path, "rb")
    if not file then
        if ngx.log then
            ngx.log(ngx.WARN,
                    "Arxignis filter: unable to read temp body file: ",
                    tostring(open_err))
        end
        return nil
    end

    local content = file:read("*a")
    file:close()

    return content
end

local function new_client(opts)
    opts = opts or {}

    local self = {
        api_url = sanitize_base_url(opts.api_url),
        api_key = opts.api_key,
        timeout = opts.timeout or DEFAULT_TIMEOUT,
        ssl_verify = opts.ssl_verify,
        http_client_factory = opts.http_client_factory
    }

    if self.ssl_verify == nil then self.ssl_verify = true end

    return setmetatable(self, filter)
end

function filter.new(opts) return new_client(opts) end

function filter.build_event_from_request(opts)
    opts = opts or {}

    if not ngx or not ngx.req then return nil, "ngx.req is not available" end

    local headers = ngx.req.get_headers() or {}
    local body = read_request_body()

    local path = ngx.var and ngx.var.uri or nil
    local query = ngx.var and ngx.var.args or nil
    local scheme = ngx.var and ngx.var.scheme or nil
    local host_header = headers["host"] or headers["Host"] or
                            (ngx.var and ngx.var.host) or nil
    local host = host_header
    if host and type(host) == "string" then
        local colon_index = host:find(":", 1, true)
        if colon_index then host = host:sub(1, colon_index - 1) end
    end
    local remote_ip = ngx.var and ngx.var.remote_addr or nil
    local port = ngx.var and tonumber(ngx.var.server_port) or nil
    local request_id = opts.request_id or
                           (ngx.var and (ngx.var.request_id or ngx.var.req_id)) or
                           nil

    local http_section = {
        method = ngx.req.get_method and ngx.req.get_method() or nil,
        path = path,
        query = query,
        host = host,
        scheme = scheme,
        port = port,
        remote_ip = remote_ip,
        user_agent = headers["user-agent"] or headers["User-Agent"],
        content_type = headers["content-type"] or headers["Content-Type"],
        headers = headers
    }

    if body then
        http_section.body = body
        http_section.body_sha256 = compute_sha256(body)
        http_section.content_length = #body
    else
        local content_length_header = headers["content-length"] or
                                          headers["Content-Length"]
        if content_length_header then
            http_section.content_length = tonumber(content_length_header)
        end
    end

    if query and query ~= "" then
        http_section.query_hash = compute_sha256(query)
    end

    local event = {
        event_type = opts.event_type or DEFAULT_EVENT_TYPE,
        schema_version = opts.schema_version or DEFAULT_SCHEMA_VERSION,
        timestamp = opts.timestamp or
            os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.now and ngx.now() or os.time()),
        request_id = request_id,
        http = http_section
    }

    if opts.additional then event.additional = opts.additional end

    return event
end

function filter:send(event, opts)
    opts = opts or {}

    if type(event) ~= "table" then return nil, "event must be a table" end

    local idempotency_key = opts.idempotency_key
    if not idempotency_key or idempotency_key == "" then
        return nil, "idempotency_key is required"
    end

    local payload, encode_err = cjson.encode(event)
    if not payload then
        return nil, "failed to encode filter event: " .. tostring(encode_err)
    end

    local method = "POST"
    if opts.method and opts.method ~= "" then
        method = tostring(opts.method):upper()
    end

    local timeout = opts.timeout or self.timeout
    local query_args = {["idempotency-key"] = idempotency_key}

    local original_event = opts.original_event
    if original_event == nil then original_event = false end
    query_args.originalEvent = original_event and "true" or "false"

    local query_string = encode_args(query_args)

    local url = self.api_url .. FILTER_PATH
    if query_string and #query_string > 0 then
        url = url .. "?" .. query_string
    end

    local headers = {["Content-Type"] = "application/json"}
    if self.api_key and self.api_key ~= "" then
        headers["Authorization"] = "Bearer " .. self.api_key
    end
    if opts.headers then
        for key, value in pairs(opts.headers) do headers[key] = value end
    end

    if ngx and ngx.log then
        local sanitized_headers = {}
        for key, value in pairs(headers) do
            if type(key) == "string" and key:lower() == "authorization" then
                sanitized_headers[key] = "***"
            else
                sanitized_headers[key] = value
            end
        end

        local headers_json = cjson.encode(sanitized_headers)
        local body_b64
        if event and event.http and event.http.body and ngx.encode_base64 then
            body_b64 = ngx.encode_base64(event.http.body)
        end

        ngx.log(ngx.INFO, "Arxignis filter outbound request: method=", method,
                " url=", url, " headers=", headers_json, " payload=", payload,
                body_b64 and (" body_b64=" .. body_b64) or "")
    end

    local ssl_verify = opts.ssl_verify
    if ssl_verify == nil then ssl_verify = self.ssl_verify end

    local http_requester
    if self.http_client_factory then
        http_requester = self.http_client_factory()
    end

    if http_requester and http_requester.request_uri then
        if http_requester.set_timeout then
            http_requester:set_timeout(timeout)
        end
        local res, request_err = http_requester:request_uri(url, {
            method = method,
            body = payload,
            headers = headers,
            ssl_verify = ssl_verify
        })
        if not res then
            return nil, "filter API request failed: " .. tostring(request_err)
        end

        local parsed_body
        if res.body and type(res.body) == "string" and #res.body > 0 then
            parsed_body = cjson.decode(res.body)
        end

        return {
            status = res.status or 0,
            headers = res.headers or {},
            body = res.body or "",
            json = parsed_body
        }, nil
    end

    local res, err = utils.http_request(url, {
        method = method,
        timeout = timeout,
        headers = headers,
        body = payload,
        ssl_verify = ssl_verify
    })

    if err then return nil, "filter API request failed: " .. tostring(err) end

    local parsed_body
    if res and res.body and type(res.body) == "string" and #res.body > 0 then
        parsed_body = cjson.decode(res.body)
    end

    if res ~= nil then
        return {
            status = res.status or 0,
            headers = res.headers or {},
            body = res.body or "",
            json = parsed_body
        }, nil
    else
        return nil, "filter API request failed: " .. tostring(err)
    end
end

return filter
