local arxignis = {_TYPE='module', _NAME='arxignis', _VERSION='1.0-0'}
local logger = require("resty.arxignis.logger")

-- Environment variable validation
local function validate_environment()
    local required_vars = {
        "ARXIGNIS_API_URL",
        "ARXIGNIS_API_KEY",
        "ARXIGNIS_CAPTCHA_SECRET_KEY",
        "ARXIGNIS_CAPTCHA_SITE_KEY",
        "ARXIGNIS_CAPTCHA_PROVIDER"
    }

    local missing_vars = {}
    local cache = ngx.shared.arxignis_cache

    for _, var_name in ipairs(required_vars) do
        local value = os.getenv(var_name)
        ngx.log(ngx.DEBUG, "Environment variable: " .. var_name .. " = " .. (value or "nil"))
        if not value or value == "" then
            table.insert(missing_vars, var_name)
        else
            -- Store in shared dictionary for later use
            cache:set(var_name, value)
        end
    end

    if #missing_vars > 0 then
        logger.error("Missing required environment variables", {
            missing_variables = table.concat(missing_vars, ", "),
            message = "Arxignis integration will not function properly without these variables"
        })
        return false
    end

    return true
end

-- Check environment variables at module load
local env_valid = validate_environment()

local mode = os.getenv("ARXIGNIS_MODE")
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

function arxignis.remediate(ipaddress)
  -- Check environment variables first
  if not env_valid then
      logger.error("Environment validation failed, skipping remediation", {
          ip_address = ipaddress,
          message = "Required environment variables are not set"
      })
      return true -- Allow request to proceed if environment is not configured
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

  -- ngx.log(ngx.DEBUG, "Remediate called with ipaddress: " .. ipaddress .. ", ja4: " .. ja4 .. ", ssl: " .. tostring(is_ssl))

  local remediation = require("resty.arxignis.remediation")
  local utils = require("resty.arxignis.utils")
  local captcha = require("resty.arxignis.captcha")

  -- Check for existing captcha token in cookies
  local cookies = ngx.var.http_cookie
  ngx.log(ngx.DEBUG, "Cookie check - cookies: " .. (cookies or "nil") .. ", IP: " .. ipaddress)
  if cookies then
    -- Parse cookies more robustly
    for cookie in cookies:gmatch("ax_captcha=([^;%s]+)") do
      ngx.log(ngx.DEBUG, "Found ax_captcha cookie: " .. cookie)
      -- Verify secure captcha token
      local token_valid = verify_captcha_token(cookie, ipaddress, ja4)
      if token_valid then
        ngx.log(ngx.DEBUG, "Valid captcha token found, allowing request")
        return true
      else
        ngx.log(ngx.DEBUG, "Invalid captcha token found, continuing")
      end
    end
  end

  local remediation_response = remediation.get(ipaddress, mode)

  -- Validate remediation response
  if not remediation_response then
    logger.warn("No remediation response received for IP", {ip_address = ipaddress})
    return true -- Allow request to proceed if remediation fails
  end

  if not remediation_response.remediation then
    logger.warn("Invalid remediation response structure for IP", {ip_address = ipaddress})
    return true -- Allow request to proceed if remediation response is invalid
  end

  if not remediation_response.remediation.action then
    logger.warn("Missing action in remediation response for IP", {ip_address = ipaddress})
    return true -- Allow request to proceed if action is missing
  end

  if remediation_response.remediation.action == "block" then
    if mode == "monitor" then
      ngx.log(ngx.WARN, "Arxignis is running in monitor mode: request allowed to proceed, but it would have been blocked under enforcement mode.")
      return true
    end

    local block_template = utils.read_file("/usr/local/openresty/luajit/lib/lua/5.1/resty/arxignis/templates/block.html")
    ngx.status = utils.http_status_codes[403]
    ngx.header.content_type = "text/html"
    ngx.say(block_template)
    ngx.exit(utils.http_status_codes[403])
  end

  if remediation_response.remediation.action == "captcha" then

    if mode == "monitor" then
      ngx.log(ngx.WARN, "Arxignis is running in monitor mode: request allowed to proceed, but it would have been challenged under enforcement mode.")
      return true
    end

    local captcha_ok = true
    local cache = ngx.shared.arxignis_cache
    local secret_key = cache:get("ARXIGNIS_CAPTCHA_SECRET_KEY")
    local site_key = cache:get("ARXIGNIS_CAPTCHA_SITE_KEY")
    local captcha_provider = cache:get("ARXIGNIS_CAPTCHA_PROVIDER")
    local captcha_template_path = cache:get("ARXIGNIS_CAPTCHA_TEMPLATE_PATH") or "/usr/local/openresty/luajit/lib/lua/5.1/resty/arxignis/templates/captcha.html"

    -- Check if captcha is properly configured
    if not secret_key or not site_key then
      logger.warn("Captcha not configured, skipping captcha challenge", {
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
        local args, err = ngx.req.get_post_args()

        if args and not err then
          -- Try to get captcha response using the proper key
          captcha_response = args["cf-turnstile-response"] or args["g-recaptcha-response"] or args["h-captcha-response"]
          ngx.log(ngx.DEBUG, "POST body parsing - args: " .. (args and "found" or "nil") .. ", captcha_response: " .. (captcha_response or "nil"))
        else
          logger.error("Error parsing POST args", {error = err or "unknown"})
        end
      end

      -- If no POST body, try URL parameters (fallback)
      if not captcha_response then
        captcha_response = ngx.var.arg_cf_turnstile_response or ngx.var.arg_g_recaptcha_response or ngx.var.arg_h_captcha_response
      end

      ngx.log(ngx.DEBUG, "Captcha check - method: " .. (ngx.var.request_method or "nil") .. ", response: " .. (captcha_response or "nil") .. ", IP: " .. ipaddress)

      if captcha_response and captcha_response ~= "" then
        -- Validate the captcha response
        local is_valid, validation_error = captcha.validate(captcha_response, ipaddress)
        ngx.log(ngx.DEBUG, "Captcha validation result: " .. tostring(is_valid) .. ", error: " .. (validation_error or "none"))

        if is_valid then
          -- Captcha solved successfully, generate JWT token and set cookie
          ngx.log(ngx.DEBUG, "Captcha validation successful, generating JWT token")

          -- Generate secure captcha token
          local captcha_token = generate_captcha_token(ipaddress, ja4)

          -- Set cookie and redirect to clear captcha state
          local cookie_value = "ax_captcha=" .. captcha_token .. "; Path=/; HttpOnly; SameSite=Strict; Max-Age=7200"
          ngx.header["Set-Cookie"] = cookie_value
          ngx.log(ngx.DEBUG, "Setting captcha cookie: " .. cookie_value)
          ngx.redirect(ngx.var.request_uri)
          return
        else
          -- Captcha validation failed, show error and captcha again
          logger.warn("Captcha validation failed", {error = validation_error or "unknown error"})
          captcha.apply()
        end
      else
        -- No captcha response, show the captcha form
        logger.warn("No captcha response, showing captcha form")
        captcha.apply()
      end
    else
      ngx.status = utils.http_status_codes[500]
      ngx.header.content_type = "text/html"
      ngx.say("Error loading captcha")
      ngx.exit(utils.http_status_codes[500])
    end
  end

  if remediation_response.remediation.action == "none" then
    return true
  end
end

return arxignis
