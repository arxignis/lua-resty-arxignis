local metrics = {_TYPE='module', _NAME='arxignis.metrics', _VERSION='1.0-0'}
local utils = require("resty.arxignis.utils")
local worker = require("resty.arxignis.worker")

-- Function to send metrics data
function metrics.metrics(env, remediation_result)
    -- Build metrics template
    local metrics_template = {
        timestamp = utils.get_iso_timestamp(),
        type = "metrics",
        clientIp = remediation_result.clientIp or "unknown",
        hostName = utils.get_host_name(),
        remediation = remediation_result.decision or "unknown",
        score = remediation_result.score or 0,
        cached = remediation_result.cached or false
    }

    -- Add metrics to batch using worker module (separate from logs)
    local success, err = pcall(worker.add_metrics_to_batch, env, metrics_template)
    if not success then
        ngx.log(ngx.ERR, "Failed to add metrics to batch: " .. (err or "unknown error"))
        return false
    end

    ngx.log(ngx.DEBUG, "Metrics added to batch successfully")
    return true
end

return metrics
