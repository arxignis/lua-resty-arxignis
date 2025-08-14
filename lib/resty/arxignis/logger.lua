local logger = {_TYPE='module', _NAME='arxignis.logger', _VERSION='1.0-0'}

local cjson = require("cjson")

-- Default log level mapping
local LOG_LEVELS = {
    emerg = 0,
    alert = 1,
    crit = 2,
    error = 3,
    warn = 4,
    notice = 5,
    info = 6,
    debug = 7
}

-- Current log level (default to info, excluding debug)
local current_level = LOG_LEVELS.info

-- Set log level
function logger.set_level(level)
    if LOG_LEVELS[level] then
        current_level = LOG_LEVELS[level]
    end
end

-- Check if level should be logged
local function should_log(level)
    return LOG_LEVELS[level] <= current_level
end

-- Format timestamp
local function format_timestamp()
    return os.date("%Y-%m-%dT%H:%M:%SZ", ngx.time())
end

-- Create log entry
local function create_log_entry(level, message, fields)
    local entry = {
        timestamp = format_timestamp(),
        level = level,
        message = message,
        request_id = ngx.var.request_id or "unknown",
        remote_addr = ngx.var.remote_addr or "unknown",
        request_uri = ngx.var.request_uri or "unknown",
        http_user_agent = ngx.var.http_user_agent or "unknown"
    }

    -- Add custom fields if provided
    if fields and type(fields) == "table" then
        for k, v in pairs(fields) do
            entry[k] = v
        end
    end

    return entry
end

-- Internal logging function
local function log_internal(level, message, fields)
    if not should_log(level) then
        return
    end

    local entry = create_log_entry(level, message, fields)
    local json_str = cjson.encode(entry)

    -- Map to nginx log levels
    local nginx_level
    if level == "emerg" then nginx_level = ngx.EMERG
    elseif level == "alert" then nginx_level = ngx.ALERT
    elseif level == "crit" then nginx_level = ngx.CRIT
    elseif level == "error" then nginx_level = ngx.ERR
    elseif level == "warn" then nginx_level = ngx.WARN
    elseif level == "notice" then nginx_level = ngx.NOTICE
    elseif level == "info" then nginx_level = ngx.INFO
    else nginx_level = ngx.INFO
    end

    return ngx.log(nginx_level, json_str)
end

-- Public logging functions
function logger.emerg(message, fields)
    return log_internal("emerg", message, fields)
end

function logger.alert(message, fields)
    return log_internal("alert", message, fields)
end

function logger.crit(message, fields)
    return log_internal("crit", message, fields)
end

function logger.error(message, fields)
    return log_internal("error", message, fields)
end

function logger.warn(message, fields)
    return log_internal("warn", message, fields)
end

function logger.notice(message, fields)
    return log_internal("notice", message, fields)
end

function logger.info(message, fields)
    return log_internal("info", message, fields)
end

-- Convenience function for security events
function logger.security_event(event_type, details, fields)
    local security_fields = {
        event_type = event_type,
        details = details,
        ssl_protocol = ngx.var.ssl_protocol or "none",
        ssl_cipher = ngx.var.ssl_cipher or "none"
    }

    if fields then
        for k, v in pairs(fields) do
            security_fields[k] = v
        end
    end

    log_internal("info", "Security event: " .. event_type, security_fields)
end

-- Convenience function for access events
function logger.access_event(action, ip_address, user_agent, fields)
    local access_fields = {
        action = action,
        ip_address = ip_address,
        user_agent = user_agent
    }

    if fields then
        for k, v in pairs(fields) do
            access_fields[k] = v
        end
    end

    log_internal("info", "Access event: " .. action, access_fields)
end

return logger
