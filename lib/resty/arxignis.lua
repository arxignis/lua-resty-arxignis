local arxignis = {_TYPE='module', _NAME='arxignis', _VERSION='1.0-0'}
local logger = require("resty.arxignis.logger")
local access_rules = require("resty.arxignis.access_rules")
local utils = require("resty.arxignis.utils")
local captcha = require("resty.arxignis.captcha")
local threat = require("resty.arxignis.threat")
local filter_module = require("resty.arxignis.filter")
local config = require("resty.arxignis.config")

-- Environment variable validation
local function validate_environment()
    local is_valid, missing_vars = config.validate()

    if not is_valid then
        logger.error("Missing required environment variables", {
            missing_variables = table.concat(missing_vars, ", "),
            message = "Arxignis integration will not function properly without these variables"
        })
        return false
    end

    -- Store configuration in shared cache for performance
    config.store_in_cache()

    return true
end

-- Check environment variables at module load
local env_valid = validate_environment()

local mode = config.get_mode()
if mode ~= "block" then
    mode = "monitor"
    logger.warn("ARXIGNIS_MODE is not set, defaulting to monitor mode")
end

-- Helper function to generate secure captcha token
local function generate_captcha_token(ipaddress, ja4)
  -- Generate a cryptographically secure random token
  local random_bytes = ngx.md5(ngx.time() .. ipaddress .. ngx.var.http_user_agent .. math.random())

  -- Create token with multiple security factors
  local token_data = {
    timestamp = ngx.time(),
    ip_hash = ngx.md5(ipaddress):sub(1, 8), -- Hash IP address
    user_agent_hash = ngx.md5(ngx.var.http_user_agent or "unknown"):sub(1, 8), -- Hash user agent
    random = random_bytes:sub(1, 16), -- Use first 16 chars of hash
    signature = ngx.md5(ipaddress .. (ngx.var.http_user_agent or "unknown") .. "SECRET_SALT"):sub(1, 16)
  }

  -- Add JA4 data to token if available and valid
  local ja4_hash = ""
  if ja4 and ja4 ~= "unknown" and ja4 ~= "" and ja4 ~= "no_ssl" then
    ja4_hash = "_" .. ngx.md5(ja4):sub(1, 8)
    token_data.ja4_hash = ja4_hash
  end

  -- Encode as simple string: captcha_timestamp_ip_hash_useragent_hash_random_signature[ja4_hash]
  local token = string.format("captcha_%d_%s_%s_%s_%s%s",
    token_data.timestamp,
    token_data.ip_hash,
    token_data.user_agent_hash,
    token_data.random,
    token_data.signature,
    ja4_hash
  )

  ngx.log(ngx.DEBUG, "Generated token: " .. token)
  return token
end

-- Helper function to verify secure captcha token
local function verify_captcha_token(token, ipaddress, ja4)
  -- Parse token components
  local parts = {}
  for part in token:gmatch("[^_]+") do
    table.insert(parts, part)
  end

  ngx.log(ngx.DEBUG, "Token validation - token: " .. token .. ", parts count: " .. #parts)
  for i, part in ipairs(parts) do
    ngx.log(ngx.DEBUG, "Part " .. i .. ": " .. part)
  end

  -- Token format: captcha_timestamp_ip_useragent_hash_random_signature[ja4_hash]
  -- Minimum parts: 6 (without JA4), 7 (with JA4)
  if #parts < 6 or parts[1] ~= "captcha" then
    ngx.log(ngx.ERR, "Token validation failed - wrong format or parts: " .. #parts)
    return false
  end

  local timestamp = tonumber(parts[2])
  local token_ip_hash = parts[3]

  ngx.log(ngx.DEBUG, "Token validation - timestamp: " .. (timestamp or "nil") .. ", token_ip_hash: " .. token_ip_hash)

  -- Validate timestamp (2 hour expiration)
  if not timestamp or (ngx.time() - timestamp) >= 7200 then
    ngx.log(ngx.DEBUG, "Token validation failed - timestamp expired or invalid")
    return false
  end

  -- Validate IP address hash
  local expected_ip_hash = ngx.md5(ipaddress):sub(1, 8)
  if token_ip_hash ~= expected_ip_hash then
    ngx.log(ngx.DEBUG, "Token validation failed - IP hash mismatch: " .. token_ip_hash .. " vs " .. expected_ip_hash)
    return false
  end

  -- Validate user agent hash
  local current_user_agent = ngx.var.http_user_agent or "unknown"
  local token_user_agent_hash = parts[4]
  local expected_user_agent_hash = ngx.md5(current_user_agent):sub(1, 8)
  ngx.log(ngx.DEBUG, "Token validation - current_user_agent: " .. current_user_agent .. ", token_hash: " .. token_user_agent_hash .. ", expected_hash: " .. expected_user_agent_hash)

  if token_user_agent_hash ~= expected_user_agent_hash then
    ngx.log(ngx.DEBUG, "Token validation failed - user agent hash mismatch")
    return false
  end

  local signature = parts[6]

  -- Validate signature (prevent tampering)
  local expected_signature = ngx.md5(ipaddress .. current_user_agent .. "SECRET_SALT"):sub(1, 16)
  ngx.log(ngx.DEBUG, "Token validation - signature: " .. signature .. ", expected: " .. expected_signature)
  if signature ~= expected_signature then
    ngx.log(ngx.DEBUG, "Token validation failed - signature mismatch")
    return false
  end

  -- Validate JA4 hash if present in token and current JA4 is available
  if #parts >= 7 and ja4 and ja4 ~= "unknown" and ja4 ~= "" and ja4 ~= "no_ssl" then
    local token_ja4_hash = parts[7]
    local expected_ja4_hash = ngx.md5(ja4):sub(1, 8)
    ngx.log(ngx.DEBUG, "Token validation - JA4 hash: " .. token_ja4_hash .. ", expected: " .. expected_ja4_hash)

    if token_ja4_hash ~= expected_ja4_hash then
      ngx.log(ngx.DEBUG, "Token validation failed - JA4 hash mismatch")
      return false
    end
  end

  ngx.log(ngx.DEBUG, "Token validation successful")
  return true
end

function arxignis.remediate(ipaddress, country, asn)
  local cache = ngx.shared.arxignis_cache

  if not env_valid then
      logger.error("Environment validation failed, skipping remediation", {
          ip_address = ipaddress,
          message = "Required environment variables are not set"
      })
      return true
  end

  local rules = access_rules.check(ipaddress, country, asn)
  if rules and rules.access_rules and rules.access_rules.action == "block" then
      if mode == "monitor" then
        logger.warn("Arxignis is running in monitor mode: request allowed to proceed, but it would have been blocked under enforcement mode.")
        return true
      end
      local block_template_path = cache:get("ARXIGNIS_BLOCK_TEMPLATE_PATH") or "/usr/local/openresty/luajit/lib/lua/5.1/resty/arxignis/templates/block.html"
      local block_template = utils.read_file(block_template_path)
      ngx.status = utils.http_status_codes[403]
      ngx.header.content_type = "text/html"
      ngx.say(block_template)
      ngx.exit(utils.http_status_codes[403])
  elseif rules == nil then
    logger.warn("No access rules found", {ip_address = ipaddress})
  elseif rules and rules.access_rules and rules.access_rules.action == "allow" then
      return true
  end

  -- Check if this is an SSL/TLS request
  local is_ssl = ngx.var.ssl_protocol ~= nil and ngx.var.ssl_protocol ~= ""

  local ja4 = ngx.var.http_ssl_ja4
  if not is_ssl then
    logger.warn("Not an SSL request - no JA4 data available or JA4 module is not loaded")
    ja4 = "no_ssl"
  elseif ja4 == nil or ja4 == "" then
    ja4 = "unknown"
  end

  -- Helper function to handle captcha challenges
  local function handle_captcha_challenge()
    local captcha_ok = true
    local secret_key = config.get_captcha_secret_key()
    local site_key = config.get_captcha_site_key()
    local captcha_provider = config.get_captcha_provider()
    local captcha_template_path = cache:get("ARXIGNIS_CAPTCHA_TEMPLATE_PATH") or "/usr/local/openresty/luajit/lib/lua/5.1/resty/arxignis/templates/captcha.html"

    -- Check if captcha is properly configured
    if not secret_key or not site_key then
      logger.error("Captcha not configured, skipping captcha challenge", {
        has_secret_key = secret_key ~= nil,
        has_site_key = site_key ~= nil
      })
      return true
    end

    if captcha_provider ~= "turnstile" and captcha_provider ~= "recaptcha" and captcha_provider ~= "hcaptcha" then
      logger.error("Invalid captcha provider set, skipping captcha", {provider = captcha_provider})
      return true
    end

    local err = captcha.new(site_key, secret_key, captcha_template_path, captcha_provider, "200")
    if err ~= nil then
      logger.error("Error loading captcha plugin", {error = err})
      captcha_ok = false
    end

    if captcha_ok then
      -- Check if there's already a captcha response from POST body
      local captcha_response = nil

      -- First try to get from POST body (for form submissions)
      if ngx.var.request_method == "POST" then
        ngx.req.read_body()
        local args, post_err = ngx.req.get_post_args()

        if args and not post_err then
          -- Try to get captcha response using the proper key
          captcha_response = args["cf-turnstile-response"] or args["g-recaptcha-response"] or args["h-captcha-response"]
          logger.debug("POST body parsing - args: " .. (args and "found" or "nil") .. ", captcha_response: " .. (captcha_response or "nil"))
        else
          logger.error("Error parsing POST args", {error = post_err or "unknown"})
        end
      end

      -- If no POST body, try URL parameters (fallback)
      if not captcha_response then
        captcha_response = ngx.var.arg_cf_turnstile_response or ngx.var.arg_g_recaptcha_response or ngx.var.arg_h_captcha_response
      end

      logger.debug("Captcha check - method: " .. (ngx.var.request_method or "nil") .. ", response: " .. (captcha_response or "nil") .. ", IP: " .. ipaddress)

      if captcha_response and captcha_response ~= "" then
        -- Validate the captcha response
        local is_valid, validation_error = captcha.validate(captcha_response, ipaddress)
        logger.debug("Captcha validation result: " .. tostring(is_valid) .. ", error: " .. (validation_error or "none"))

        if is_valid then
          -- Captcha solved successfully, generate JWT token and set cookie
          logger.debug("Captcha validation successful, generating JWT token")

          -- Generate secure captcha token
          local captcha_token = generate_captcha_token(ipaddress, ja4)

          -- Set cookie so future requests bypass the challenge
          local cookie_value = "ax_captcha=" .. captcha_token .. "; Path=/; HttpOnly; SameSite=Strict; Max-Age=7200"
          ngx.header["Set-Cookie"] = cookie_value
          logger.debug("Setting captcha cookie: " .. cookie_value)
          threat_response.advice = "allow"
        else
          -- Captcha validation failed, show error and captcha again
          logger.warn("Captcha validation failed", {error = validation_error or "unknown error"})
          captcha.apply()
          return true
        end
      else
        -- No captcha response, show the captcha form
        logger.warn("No captcha response, showing captcha form")
        captcha.apply()
        return true
      end
    else
      ngx.status = utils.http_status_codes[500]
      ngx.header.content_type = "text/html"
      ngx.say("Error loading captcha")
      ngx.exit(utils.http_status_codes[500])
    end

    return true
  end

  -- Check for existing captcha token in cookies
  local cookies = ngx.var.http_cookie
  logger.debug("Cookie check - cookies: " .. (cookies or "nil") .. ", IP: " .. ipaddress)
  if cookies then
  -- Parse cookies more robustly
  for cookie in cookies:gmatch("ax_captcha=([^;%s]+)") do
    logger.debug("Found ax_captcha cookie: " .. cookie)
    -- Verify secure captcha token
    local token_valid = verify_captcha_token(cookie, ipaddress, ja4)
    if token_valid then
      logger.debug("Valid captcha token found, allowing request to proceed to filter analysis")
      -- Return early with allow response
      return true
    else
      logger.debug("Invalid captcha token found, continuing")
    end
  end
end

local threat_response = threat.get(ipaddress, mode)
  -- Validate threat response
  if not threat_response then
    logger.warn("No threat response received for IP", {ip_address = ipaddress})
    return true -- Allow request to proceed if threat fails
  end

  if not threat_response.intel then
    logger.warn("Invalid threat response structure for IP", {ip_address = ipaddress})
    return true -- Allow request to proceed if threat response is invalid
  end

  if not threat_response.advice then
    logger.warn("Missing action in threat response for IP", {ip_address = ipaddress})
    return true -- Allow request to proceed if action is missing
  end

  if threat_response.advice == "block" then
    if mode == "monitor" then
      logger.warn("Arxignis is running in monitor mode: request allowed to proceed, but it would have been blocked under enforcement mode.")
      return true
    end
    local block_template_path = cache:get("ARXIGNIS_BLOCK_TEMPLATE_PATH") or "/usr/local/openresty/luajit/lib/lua/5.1/resty/arxignis/templates/block.html"
    local block_template = utils.read_file(block_template_path)
    ngx.status = utils.http_status_codes[403]
    ngx.header.content_type = "text/html"
    ngx.say(block_template)
    ngx.exit(utils.http_status_codes[403])
  end

  if threat_response.advice == "challenge" then
    if mode == "monitor" then
      logger.warn("Arxignis is running in monitor mode: request allowed to proceed, but it would have been challenged under enforcement mode.")
      return true
    end

    -- Use the extracted captcha challenge function
    local challenge_result = handle_captcha_challenge()
    if challenge_result then
      threat_response.advice = "allow"
    end
    return challenge_result
  end

  -- Run WAF analysis and content scanning when remediation allows request
  local additional = {
    remediation = threat_response and threat_response.advice or "unknown",
    threat_score = threat_response and threat_response.intel and threat_response.intel.score or nil,
    threat_rule = threat_response and threat_response.intel and threat_response.intel.rule_id or nil,
    mode = mode,
  }

  local ok_event, event_or_err = pcall(filter_module.build_event_from_request, {
    additional = additional,
  })

  if not ok_event then
    logger.error("Failed to build Arxignis filter event", { error = event_or_err })
    return true
  end

  local filter_event = event_or_err
  if filter_event and (not filter_event.tenant_id or filter_event.tenant_id == "") and threat_response and threat_response.tenant_id then
    filter_event.tenant_id = threat_response.tenant_id
  end

  local function respond_with_block(reason, source, payload)
    local metadata = {
      reason = reason or "Request blocked",
      source = source or "arxignis",
      payload = payload,
    }

    if mode == "monitor" then
      logger.warn("Arxignis would block request in block mode", metadata)
      return true
    end

    local block_template_path = cache:get("ARXIGNIS_BLOCK_TEMPLATE_PATH") or "/usr/local/openresty/luajit/lib/lua/5.1/resty/arxignis/templates/block.html"
    local block_template = utils.read_file(block_template_path)
    logger.info("Blocking request due to Arxignis decision", metadata)
    ngx.status = utils.http_status_codes[403]
    ngx.header.content_type = "text/html"
    ngx.say(block_template)
    ngx.exit(utils.http_status_codes[403])
  end

  local function respond_with_challenge(reason, source, payload)
    local metadata = {
      reason = reason or "Request challenged",
      source = source or "arxignis",
      payload = payload,
    }

    if mode == "monitor" then
      logger.warn("Arxignis would challenge request in block mode", metadata)
      return true
    end

    logger.info("Challenging request due to Arxignis decision", metadata)

    -- Use the extracted captcha challenge function
    return handle_captcha_challenge()
  end

  local headers = ngx.req.get_headers() or {}
  local filter_client = filter_module.new({
    api_url = config.get_api_url(),
    api_key = config.get_api_key(),
    ssl_verify = true,
  })

  local http_section = filter_event and filter_event.http or {}
  logger.debug("Arxignis filter request metadata", {
    method = http_section.method,
    path = http_section.path,
    content_type = http_section.content_type,
    content_length = http_section.content_length,
    has_body = http_section.body and http_section.body ~= "",
  })

  local filter_response, filter_err = filter_client:send(filter_event, {
    original_event = false,
  })

  local waf_action = "allow"
  local waf_reason = nil
  local waf_details = nil

  if filter_response and filter_response.json then
    waf_action = filter_response.json.action or "allow"
    waf_details = filter_response.json.details
    waf_reason = filter_response.json.reason

      if waf_action == "block" then
        return respond_with_block(waf_reason or "Request blocked by WAF", "waf", filter_response and filter_response.json or nil)
      elseif waf_action == "challenge" then
        return respond_with_challenge(waf_reason or "Request challenged by WAF", "waf", filter_response and filter_response.json or nil)
      end
  elseif filter_err then
    logger.warn("Arxignis WAF request failed", { error = filter_err })
  end

  if waf_action == "block" then
    return respond_with_block(waf_reason or "Request blocked by WAF", "waf", filter_response and filter_response.json or nil)
  end

  local should_scan = filter_event and filter_event.http and filter_event.http.body and filter_event.http.body ~= ""
  if not should_scan then
    return true
  end

  local scan_request, scan_request_err = filter_module.build_scan_request_from_event(filter_event)
  if not scan_request then
    logger.warn("Unable to build content scan request", { error = scan_request_err })
    return true
  end

  local scan_response, scan_err = filter_client:scan(scan_request)

  if scan_response and scan_response.json then
    local scan_json = scan_response.json
    local virus_detected = scan_json.virus_detected or (scan_json.files_infected and scan_json.files_infected > 0)
    if virus_detected then
      local virus_reason = scan_json.virus_name and ("Request blocked due to malware detection: " .. scan_json.virus_name) or "Request blocked due to malware detection"
      return respond_with_block(virus_reason, "content_scan", scan_json)
    end

    logger.info("Arxignis content scan response", {
      status = scan_response.status,
      json = scan_json,
    })
  elseif scan_err then
    logger.warn("Arxignis content scan request failed", { error = scan_err })
  end

  return true
end

return arxignis
