local cjson = require("cjson")
local utils = require("resty.arxignis.utils")
local logger = require("resty.arxignis.logger")
local metrics = require("resty.arxignis.metrics")
local config = require("resty.arxignis.config")

local access_rules = {_TYPE='module', _NAME='arxignis.access_rules', _VERSION='1.0-0'}
local rule_id = config.get_access_rule_id()

if not rule_id or rule_id == "" then
  logger.warn("ARXIGNIS_ACCESS_RULE_ID not set; access rules disabled")
  -- Return a module with disabled functionality instead of nil
  function access_rules.get()
    return nil
  end
  function access_rules.get_access_rules()
    return nil
  end
  function access_rules.evaluate(_, _)
    return nil
  end
  function access_rules.check(_, _, _)
    return nil
  end
  return access_rules
end

-- Flatten resolved access rule categories into a simple list of CIDRs/IPs
local function collect_ip_ranges(category)
  if not category then
    return {}
  end

  local ranges = {}

  -- Country: array of maps like { US = [cidr...] }
  if type(category.country) == "table" then
    for _, item in ipairs(category.country) do
      if type(item) == "table" then
        for _, ips in pairs(item) do
          if type(ips) == "table" then
            for _, cidr in ipairs(ips) do
              table.insert(ranges, cidr)
            end
          end
        end
      end
    end
  end

  -- ASN: array of maps like { AS12345 = [cidr...] }
  if type(category.asn) == "table" then
    for _, item in ipairs(category.asn) do
      if type(item) == "table" then
        for _, ips in pairs(item) do
          if type(ips) == "table" then
            for _, cidr in ipairs(ips) do
              table.insert(ranges, cidr)
            end
          end
        end
      end
    end
  end

  -- IPs: direct list of IPs/CIDRs
  if type(category.ips) == "table" then
    for _, cidr in ipairs(category.ips) do
      table.insert(ranges, cidr)
    end
  end

  return ranges
end

-- Normalize API response into list of { id, name, allow_ips, block_ips }
local function normalize_rules(data)
  local out = {}
  if type(data) ~= "table" then
    return out
  end

  -- The API can return either a single object (data is table with fields)
  -- or a list (data is array). Handle both.
  local items = data
  if data.id ~= nil or data.name ~= nil then
    items = { data }
  end

  for _, rule in ipairs(items) do
    local allow_ips = {}
    local block_ips = {}

    if type(rule.allow) == "table" then
      allow_ips = collect_ip_ranges(rule.allow)
    end
    if type(rule.block) == "table" then
      block_ips = collect_ip_ranges(rule.block)
    end

    table.insert(out, {
      id = rule.id or rule.ID or "unknown",
      name = rule.name or "",
      allow_ips = allow_ips,
      block_ips = block_ips,
      allow = rule.allow,  -- Preserve original allow data for country/ASN matching
      block = rule.block,  -- Preserve original block data for country/ASN matching
    })
  end

  return out
end

-- Fetch access rules from remediation-api (resolved form)
local function has_any_ip_ranges(rules)
  if type(rules) ~= "table" then
    return false
  end
  for _, r in ipairs(rules) do
    if (r.allow_ips and #r.allow_ips > 0) or (r.block_ips and #r.block_ips > 0) then
      return true
    end
  end
  return false
end

local function fetch_rules(resolve)
  local api_url = config.get_api_url()
  if not api_url or api_url == "" then
    logger.error("ARXIGNIS_API_URL not set; access rules disabled")
    return nil, "missing_api_url"
  end

  if rule_id == nil or rule_id == "" then
    logger.warn("ARXIGNIS_ACCESS_RULE_ID not set; access rules disabled")
    return nil, "missing_rule_id"
  end

  local url = api_url .. "/access-rules/" .. rule_id .. "?resolve=" .. tostring(resolve)
  local timeout = 10000
  local ssl_verify = true

  local res, err = utils.get_http_request(url, timeout, config.get_api_key(), ssl_verify)
  if err then
    return nil, err
  end
  if not res or res.status ~= 200 or not res.body then
    return nil, "bad_status_" .. tostring(res and res.status or "nil")
  end

  local ok, decoded = pcall(cjson.decode, res.body)
  if not ok or type(decoded) ~= "table" then
    return nil, "invalid_json"
  end

  -- API schema: { success=true, data=[...] } or { success=true, data={...} }
  if not decoded.success then
    return nil, "api_error"
  end

  local normalized = normalize_rules(decoded.data)
  logger.debug("Normalized rules: " .. require("cjson").encode(normalized))
  return normalized, nil
end

-- Public: for compatibility with tests using get_access_rules()
function access_rules.get_access_rules(resolve)
  local function loader()
    local rules, err = fetch_rules(resolve)
    if not rules then
      logger.warn("Failed to fetch access rules", { error = tostring(err) })
      return nil
    end
    return rules
  end

  if _G.arxignis_cache and _G.arxignis_cache.get then
    local cache_key = "access_rules:" .. rule_id
    local rules, err, hit = _G.arxignis_cache:get(cache_key, nil, loader, { ttl = 300, negative_ttl = 30 })
    if err then
      logger.warn("mlcache error while loading access rules", { error = tostring(err) })
    end
    logger.debug("access_rules cache hit_level: " .. tostring(hit))
    return rules, err
  else
    return loader()
  end
end

-- Public: used by remediation.lua
function access_rules.check(ipaddress, country, asn)
  local resolve = true
  if country and country ~= "" and asn and asn ~= "" then
    resolve = false
  end

  local rules = access_rules.get_access_rules(resolve)
  if rules and rules ~= nil then
    local rule_result = access_rules.evaluate(ipaddress, country, asn, rules, resolve)
    if rule_result then
      logger.info("Access rule match found for IP", {
        ip_address = ipaddress,
        action = rule_result.action,
        ruleId = rule_result.ruleId
      })

      -- Create response from rule result
      local response = {
        success = true,
        access_rules = {
          ip = ipaddress,
          ruleId = rule_result.ruleId,
          action = rule_result.action,
          expired = rule_result.expired or 600
        }
      }

      return response
    end
  end
end

-- Check if IP matches a list of CIDRs/IPs (IPv4)
local function ip_matches_any(ip, cidrs)
  if type(cidrs) ~= "table" then
    return false
  end
  for _, cidr in ipairs(cidrs) do
    if utils.is_ip_in_cidr(ip, cidr) then
      return true
    end
  end
  return false
end

-- Check if country/ASN matches any in the rule's allow/block lists
local function country_asn_matches(rule, country, asn, is_allow)
  logger.debug("Country/ASN matches called with country: " .. country .. ", asn: " .. asn .. ", is_allow: " .. tostring(is_allow))
  local target = is_allow and rule.allow or rule.block
  if not target then
    return false
  end

  -- Check country match
  if country and country ~= "" and type(target.country) == "table" then
    for _, country_code in ipairs(target.country) do
      if country_code == country then
        return true
      end
    end
  end

  -- Check ASN match
  if asn and asn ~= "" and type(target.asn) == "table" then
    for _, asn_code in ipairs(target.asn) do
      if asn_code == asn then
        return true
      end
    end
  end

  return false
end

-- Evaluate IP against normalized rules
-- Returns { action = "block"|"allow", ruleId = <id>, expired = <ttl> } or nil
function access_rules.evaluate(ip, country, asn, rules, resolve)
  logger.debug("Evaluate called with ip: " .. " resolve: " .. tostring(resolve) .. " rules: " .. require("cjson").encode(rules))

  if has_any_ip_ranges(rules) then
    logger.debug("Has any IP ranges")
  else
    logger.debug("No IP ranges")
  end

  if not ip or ip == "" then
    logger.debug("IP is nil or empty")
    return nil
  end
  if type(rules) ~= "table" then
    logger.debug("Rules is not a table")
    return nil
  end

  -- Precedence: block overrides allow; first match wins
  for _, rule in ipairs(rules) do
    local block_match = false
    local allow_match = false

    if resolve == false and (country or asn) then
      -- When resolve=false, check country/ASN directly from original rule data
      -- We need to get the original rule data for this
      block_match = country_asn_matches(rule, country, asn, false)
      allow_match = country_asn_matches(rule, country, asn, true)
    else
      -- When resolve=true or no country/ASN, check resolved IP ranges
      block_match = ip_matches_any(ip, rule.block_ips)
      allow_match = ip_matches_any(ip, rule.allow_ips)
    end

    -- Check block rules first
    if block_match then
      local metrics_data = {
        clientIp = ip,
        decision = "block",
        ruleId = rule.id,
        source = "access_rules"
      }
      metrics.metrics(config.get_env(), metrics_data)
      return { action = "block", ruleId = rule.id, expired = 600 }
    end

    -- Check allow rules
    if allow_match then
      return { action = "allow", ruleId = rule.id, expired = 600 }
    end
  end
  return { action = "none", ruleId = "none", expired = 30 }
end

return access_rules


