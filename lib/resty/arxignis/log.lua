local utils = require "resty.arxignis.utils"
local worker = require "resty.arxignis.worker"

local log = {_TYPE='module', _NAME='arxignis.log', _VERSION='1.0-0'}

-- Version constant
local VERSION = '0.0.1'

-- Main logging function
function log.log(env, custom_template, client_ip)
    -- Get host name
    local host_name = utils.get_host_name()

    -- Get SSL variables
    local ssl_vars = utils.get_ssl_vars()

    -- Get request headers
    local headers = utils.get_request_headers()

    -- Build log template
    local log_template
    if custom_template then
        -- Use custom template (e.g., for telemetry)
        log_template = custom_template
    else
        -- Build default log template
        log_template = {
            timestamp = utils.get_iso_timestamp(),
            version = VERSION,
            clientIp = client_ip,
            hostName = host_name,
            tls = {
                version = utils.safe_string(ssl_vars.ssl_protocol),
                cipher = utils.safe_string(ssl_vars.http_ssl_cipher),
                ja4 = {
                    ja4 = utils.safe_string(ssl_vars.http_ssl_ja4),
                    ja4_string = utils.safe_string(ssl_vars.http_ssl_ja4_string),
                    ja4one = utils.safe_string(ssl_vars.http_ssl_ja4one),
                    ja4s = utils.safe_string(ssl_vars.http_ssl_ja4s),
                    ja4s_string = utils.safe_string(ssl_vars.http_ssl_ja4s_string),
                    ja4h = utils.safe_string(ssl_vars.http_ssl_ja4h),
                    ja4h_string = utils.safe_string(ssl_vars.http_ssl_ja4h_string),
                    ja4t = utils.safe_string(ssl_vars.http_ssl_ja4t),
                    ja4t_string = utils.safe_string(ssl_vars.http_ssl_ja4t_string),
                    ja4ts = utils.safe_string(ssl_vars.http_ssl_ja4ts),
                    ja4ts_string = utils.safe_string(ssl_vars.http_ssl_ja4ts_string),
                    ja4x = utils.safe_string(ssl_vars.http_ssl_ja4x),
                    ja4l = utils.safe_string(ssl_vars.http_ssl_ja4l),
                },
            },
            http = {
                method = ngx.req.get_method(),
                url = ngx.var.request_uri or '',
                headers = headers,
                body = ngx.var.request_body or '',
            },
            additional = {},
        }
    end

    -- Add to batch using worker module
    local success, err = pcall(worker.add_log_to_batch, env, log_template)
    if not success then
        ngx.log(ngx.ERR, "Failed to add log to batch: " .. (err or "unknown error"))
        return false
    end

    -- Return the log template for immediate use
    return log_template
end

-- Re-export worker functions for convenience
log.start_flush_timers = worker.start_flush_timers
log.flush_remaining_logs = worker.flush_remaining_logs
log.flush_remaining_metrics = worker.flush_remaining_metrics

return log
