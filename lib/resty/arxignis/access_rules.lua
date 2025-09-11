local cjson = require("cjson")
local utils = require("resty.arxignis.utils")
local logger = require("resty.arxignis.logger")

local access_rules = {_TYPE='module', _NAME='arxignis.access_rules', _VERSION='1.0-0'}

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

local function fetch_rules()
  local api_url = os.getenv("ARXIGNIS_API_URL")
  local api_key = os.getenv("ARXIGNIS_API_KEY")

  if not api_url or api_url == "" then
    logger.warn("ARXIGNIS_API_URL not set; access rules disabled")
    return nil, "missing_api_url"
  end

  local url = api_url .. "/v1/access-rules?resolve=true&limit=1000&page=1"
  local timeout = 2000
  local ssl_verify = true

  local res, err = utils.get_http_request(url, timeout, api_key, ssl_verify)
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

  -- If resolve=true yields no usable IP ranges (e.g., GeoIP data unavailable),
  -- fallback to resolve=false to at least honor explicit IP lists.
  if not has_any_ip_ranges(normalized) then
    logger.warn("Resolved access rules contained no IP ranges; falling back to resolve=false")
    local url_unresolved = api_url .. "/v1/access-rules?resolve=false&limit=1000&page=1"
    local res2, err2 = utils.get_http_request(url_unresolved, timeout, api_key, ssl_verify)
    if not err2 and res2 and res2.status == 200 and res2.body then
      local ok2, decoded2 = pcall(cjson.decode, res2.body)
      if ok2 and decoded2 and decoded2.success then
        local normalized2 = normalize_rules(decoded2.data)
        return normalized2, nil
      end
    end
  end

  return normalized, nil
end

-- Public: for compatibility with tests using get_access_rules()
function access_rules.get_access_rules()
  local function loader()
    local rules, err = fetch_rules()
    if not rules then
      logger.warn("Failed to fetch access rules", { error = tostring(err) })
      return {}
    end
    return rules
  end

  if _G.arxignis_cache and _G.arxignis_cache.get then
    local cache_key = "access_rules_resolved"
    local rules, err, hit = _G.arxignis_cache:get(cache_key, nil, loader)
    if err then
      logger.warn("mlcache error while loading access rules", { error = tostring(err) })
    end
    ngx.log(ngx.DEBUG, "access_rules cache hit_level: " .. tostring(hit))
    return rules, err
  else
    return loader()
  end
end

-- Public: used by remediation.lua
function access_rules.get()
  local rules = access_rules.get_access_rules()
  return rules
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

-- Evaluate IP against normalized rules
-- Returns { action = "block"|"allow", ruleId = <id>, expired = <ttl> } or nil
function access_rules.evaluate(ip, rules)
  if not ip or ip == "" then
    return nil
  end
  if type(rules) ~= "table" then
    return nil
  end

  -- Precedence: block overrides allow; first match wins
  for _, rule in ipairs(rules) do
    if ip_matches_any(ip, rule.block_ips) then
      return { action = "block", ruleId = rule.id, expired = 600 }
    end
    if ip_matches_any(ip, rule.allow_ips) then
      return { action = "allow", ruleId = rule.id, expired = 600 }
    end
  end

  return nil
end

return access_rules


