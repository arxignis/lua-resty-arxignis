local threat = {_TYPE='module', _NAME='arxignis.threat', _VERSION='1.0-0'}
local utils = require("resty.arxignis.utils")
local cjson = require("cjson")
local logger = require("resty.arxignis.logger")
local log_module = require("resty.arxignis.log")
local metrics = require("resty.arxignis.metrics")
local config = require("resty.arxignis.config")


local DEFAULT_RESPONSE = {
    schema_version = "1.0",
    tenant_id = "00000000-0000-0000-0000-000000000000",
    ip = "0.0.0.0",
    intel = {
        score = 0,
        confidence = 0,
        score_version = "2025-09-01",
        categories = {},
        tags = {},
        first_seen = "",
        last_seen = "",
        source_count = 0,
        reason_code = "NO_DATA",
        reason_summary = "No threat data available",
        rule_id = "none"
    },
    context = {
        asn = 0,
        org = "Unknown",
        ip_version = 4,
        geo = {
            country = "Unknown"
        }
    },
    advice = "allow",
    ttl_s = 60,
    generated_at = os.date("!%Y-%m-%dT%H:%M:%SZ")
}

function threat.get(ipaddress, mode)
  local log_data = log_module.log(config.get_env(), nil, ipaddress)

  -- Ensure we have valid log data
  if not log_data then
    log_data = {
      timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
      version = "0.0.1",
      clientIp = ipaddress,
      hostName = ngx.var.host or "unknown",
      http = {
        method = ngx.req.get_method(),
        url = ngx.var.request_uri or '',
      }
    }
  end

  -- Validate IP address early
  if not ipaddress or ipaddress == "" then
    logger.warn("No IP address provided for threat lookup")
    return DEFAULT_RESPONSE
  end

  -- Fall back to remediation API if no access rule matches
  local function callback()

    local api_url = config.get_api_url()
    if not api_url or api_url == "" then
        logger.warn("ARXIGNIS_API_URL not set, using default response")
        return DEFAULT_RESPONSE
    end

    local url = api_url .. "/threat?ip=" .. ipaddress
    local timeout = 1000
    local api_key = config.get_api_key()
    local ssl_verify = true

    local res, err = utils.get_http_request(url, timeout, api_key, ssl_verify)

    if err then
        logger.error("Failed to get threat for IP", {ip_address = ipaddress, error = err})
        return DEFAULT_RESPONSE
    end

    if not res then
        logger.error("No response received from threat API for IP", {ip_address = ipaddress})
        return DEFAULT_RESPONSE
    end

    if res.status ~= 200 then
        logger.error("Threat API returned non-200 status", {ip_address = ipaddress, status = res.status or "unknown"})
        return DEFAULT_RESPONSE
    end

    if not res.body or res.body == "" then
        logger.error("Empty response body from threat API for IP", {ip_address = ipaddress})
        return DEFAULT_RESPONSE
    end

    -- Try to parse JSON response
    local success, result = pcall(cjson.decode, res.body)
    if not success then
        logger.error("Failed to parse threat API response for IP", {ip_address = ipaddress, error = tostring(result)})
        return DEFAULT_RESPONSE
    end

    if not result then
        logger.error("Nil result from threat API response for IP", {ip_address = ipaddress, missing_field = "threat"})
        return DEFAULT_RESPONSE
    end

    -- Validate response structure
    if not result.intel or not result.advice then
        logger.info(res.body)
        logger.error("Invalid threat response structure for IP", {ip_address = ipaddress, missing_field = "threat.advice"})
        return DEFAULT_RESPONSE
    end

    -- Ensure required fields have default values
    if not result.intel.rule_id then
        result.intel.rule_id = "unknown"
    end
    if not result.ttl_s then
        result.threat.ttl_s = 600
    end

    logger.info("Threat response for IP", {
        ip_address = ipaddress,
        action = result.advice,
        ruleId = result.intel.rule_id or "unknown"
    })

    return result
  end

  local threat_response_cache, err, hit_level = arxignis_cache:get(ngx.md5(ipaddress), nil, callback, ipaddress, { ttl = 120, negative_ttl = 20 })

  if err then
    logger.error("Error getting threat response from cache", {error = err})
    return DEFAULT_RESPONSE
  end

  -- Validate threat response cache
  if not threat_response_cache then
    logger.error("No threat response cache received", {ip_address = ipaddress})
    return DEFAULT_RESPONSE
  end

  if not threat_response_cache.intel then
    logger.error("Invalid threat response cache structure for Intel", {ip_address = ipaddress})
    return DEFAULT_RESPONSE
  end

  ngx.log(ngx.DEBUG, "Cache hit level: " .. hit_level)

  -- Send metrics data
  local metrics_data = {
    clientIp = ipaddress,
    remediation = threat_response_cache.advice or "none",
    ruleId = threat_response_cache.intel and threat_response_cache.intel.rule_id or "unknown",
  }

  if threat_response_cache.advice ~= "none" then
    if mode == "block" then
      metrics.metrics(config.get_env(), metrics_data)
    end
  end

      -- Store in secondary cache for future reference
  local secondary_cache_key = "threat:" .. ipaddress
  local secondary_cache = arxignis_cache:get(ngx.md5(secondary_cache_key), nil, nil, nil, { ipc_shm = "arxignis_cache" })

  if not secondary_cache then
    -- Set secondary cache with TTL from threat response and ipc_shm
    local ttl = threat_response_cache.ttl_s or 600
    local success, cache_err = pcall(function()
      arxignis_cache:set(ngx.md5(secondary_cache_key), threat_response_cache, {
        ttl = ttl,
        ipc_shm = "arxignis_cache"
      })
    end)
    if not success then
      logger.warn("Failed to set secondary cache", {ip_address = ipaddress, error = cache_err})
    end
  end

  return threat_response_cache
end

return threat
