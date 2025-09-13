local remediation = {_TYPE='module', _NAME='arxignis.remediation', _VERSION='1.0-0'}
local utils = require("resty.arxignis.utils")
local cjson = require("cjson")
local logger = require("resty.arxignis.logger")
local log_module = require("resty.arxignis.log")
local metrics = require("resty.arxignis.metrics")
local access_rules = require("resty.arxignis.access_rules")

-- Default fallback response when API fails
local DEFAULT_RESPONSE = {
    success = true,
    remediation = {
        ip = "0.0.0.0",
        ruleId = "unknown",
        action = "none",
        expired = 600
    }
}

function remediation.get(ipaddress, mode)
  -- Log the remediation request
  local log_env = {
    ARXIGNIS_API_URL = os.getenv("ARXIGNIS_API_URL"),
    ARXIGNIS_API_KEY = os.getenv("ARXIGNIS_API_KEY")
  }

  -- Generate log data for this request
  local log_data = log_module.log(log_env, nil, ipaddress)

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
    logger.warn("No IP address provided for remediation lookup")
    return DEFAULT_RESPONSE
  end

  -- First try to evaluate using access rules
  local rules = access_rules.get()
  if rules then
    local rule_result = access_rules.evaluate(ipaddress, rules)
    if rule_result then
      logger.info("Access rule match found for IP", {
        ip_address = ipaddress,
        action = rule_result.action,
        ruleId = rule_result.ruleId
      })
      
      -- Create response from rule result
      local response = {
        success = true,
        remediation = {
          ip = ipaddress,
          ruleId = rule_result.ruleId,
          action = rule_result.action,
          expired = rule_result.expired or 600
        }
      }
      
      -- Send metrics for access rule hit
      local metrics_data = {
        clientIp = ipaddress,
        decision = rule_result.action or "unknown",
        ruleId = rule_result.ruleId or "unknown",
        cached = true,
        source = "access_rules"
      }
      metrics.metrics(log_env, metrics_data)
      
      return response
    end
  end

  -- Fall back to remediation API if no access rule matches
  local function callback()

    local api_url = os.getenv("ARXIGNIS_API_URL")
    if not api_url or api_url == "" then
        logger.warn("ARXIGNIS_API_URL not set, using default response")
        return DEFAULT_RESPONSE
    end

    local url = api_url .. "/remediation/" .. ipaddress
    local timeout = 1000
    local api_key = os.getenv("ARXIGNIS_API_KEY")
    local ssl_verify = true

        -- Convert log data to JSON
    local body_json, err_json = cjson.encode(log_data)
    if err_json then
        logger.error("Failed to encode request body", {ip_address = ipaddress, error = err_json})
        return DEFAULT_RESPONSE
    end

    logger.info("Requesting remediation for IP", {ip_address = ipaddress})

    local res, err = utils.post_remediation_http_request(url, timeout, api_key, ssl_verify, body_json)

    if err then
        logger.error("Failed to get remediation for IP", {ip_address = ipaddress, error = err})
        return DEFAULT_RESPONSE
    end

    if not res then
        logger.error("No response received from remediation API for IP", {ip_address = ipaddress})
        return DEFAULT_RESPONSE
    end

    if res.status ~= 200 then
        logger.error("Remediation API returned non-200 status", {ip_address = ipaddress, status = res.status or "unknown"})
        return DEFAULT_RESPONSE
    end

    if not res.body or res.body == "" then
        logger.error("Empty response body from remediation API for IP", {ip_address = ipaddress})
        return DEFAULT_RESPONSE
    end

    -- Try to parse JSON response
    local success, result = pcall(cjson.decode, res.body)
    if not success then
        logger.error("Failed to parse remediation API response for IP", {ip_address = ipaddress, error = tostring(result)})
        return DEFAULT_RESPONSE
    end

    if not result then
        logger.error("Nil result from remediation API response for IP", {ip_address = ipaddress})
        return DEFAULT_RESPONSE
    end

    -- Validate response structure
    if not result.remediation or not result.remediation.action then
        logger.error("Invalid remediation response structure for IP", {ip_address = ipaddress, missing_field = "remediation.action"})
        return DEFAULT_RESPONSE
    end

    -- Ensure required fields have default values
    if not result.remediation.ruleId then
        result.remediation.ruleId = "unknown"
    end
    if not result.remediation.expired then
        result.remediation.expired = 600
    end

    logger.info("Remediation response for IP", {
        ip_address = ipaddress,
        action = result.remediation.action,
        ruleId = result.remediation.ruleId or "unknown"
    })

    return result
  end

  local rem_cache, err, hit_level = arxignis_cache:get(ngx.md5(ipaddress), nil, callback, ipaddress, { ttl = 120, negative_ttl = 20 })

  if err then
    logger.error("Error getting remediation from cache", {error = err})
    return DEFAULT_RESPONSE
  end
  ngx.log(ngx.DEBUG, "Cache hit level: " .. hit_level)

  -- Send metrics data
  local metrics_data = {
    clientIp = ipaddress,
    remediation = rem_cache.remediation.action or "none",
    ruleId = rem_cache.remediation.ruleId or "unknown",
  }

  if rem_cache.remediation.action ~= "none" then
    if mode == "block" then
      metrics.metrics(log_env, metrics_data)
    end
  end

      -- Store in secondary cache for future reference
  local secondary_cache_key = "remediation:" .. ipaddress
  local secondary_cache = arxignis_cache:get(ngx.md5(secondary_cache_key), nil, nil, nil, { ipc_shm = "arxignis_cache" })

  if not secondary_cache then
    -- Set secondary cache with TTL from remediation response and ipc_shm
    local ttl = rem_cache.remediation.expired or 600
    local success, cache_err = pcall(function()
      arxignis_cache:set(ngx.md5(secondary_cache_key), rem_cache, {
        ttl = ttl,
        ipc_shm = "arxignis_cache"
      })
    end)
    if not success then
      logger.warn("Failed to set secondary cache", {ip_address = ipaddress, error = cache_err})
    end
  end

  return rem_cache
end

return remediation
