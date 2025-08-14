local http = require("resty.http")
local cjson = require("cjson")
local utils = require("resty.arxignis.utils")
local template = require("resty.arxignis.template")
local logger = require("resty.arxignis.logger")

local captcha = {_TYPE='module', _NAME='arxignis.captcha', _VERSION='1.0-0'}

-- Constants
local CAPTCHA_PROVIDERS = {
    recaptcha = {
        backend_url = "https://www.recaptcha.net/recaptcha/api/siteverify",
        frontend_js = "https://www.recaptcha.net/recaptcha/api.js",
        frontend_key = "g-recaptcha",
        response_key = "g-recaptcha-response"
    },
    hcaptcha = {
        backend_url = "https://hcaptcha.com/siteverify",
        frontend_js = "https://js.hcaptcha.com/1/api.js",
        frontend_key = "h-captcha",
        response_key = "h-captcha-response"
    },
    turnstile = {
        backend_url = "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        frontend_js = "https://challenges.cloudflare.com/turnstile/v0/api.js",
        frontend_key = "cf-turnstile",
        response_key = "cf-turnstile-response"
    }
}

local HTTP_TIMEOUT = 2000
local DEFAULT_RET_CODE = ngx.HTTP_OK

-- Module state
local module_state = {
    secret_key = "",
    site_key = "",
    template = "",
    captcha_provider = nil,
    ret_code = DEFAULT_RET_CODE
}

-- Helper functions
local function validate_captcha_provider(provider)
    if not provider or not CAPTCHA_PROVIDERS[provider] then
        return false, "Unsupported captcha provider: " .. tostring(provider)
    end
    return true, nil
end

local function validate_required_params(site_key, secret_key, template_path)
    if not site_key or site_key == "" then
        return false, "No captcha site key provided"
    end

    if not secret_key or secret_key == "" then
        return false, "No captcha secret key provided"
    end

    if not template_path then
        return false, "CAPTCHA_TEMPLATE_PATH variable is empty"
    end

    if not utils.file_exist(template_path) then
        return false, "Captcha template file doesn't exist: " .. template_path
    end

    return true, nil
end

local function validate_http_code(http_status_code)
    if not http_status_code or http_status_code == 0 or http_status_code == "" then
        return DEFAULT_RET_CODE
    end

    for k, v in pairs(utils.HTTP_CODE) do
        if k == http_status_code then
            return v
        end
    end

    logger.error("CAPTCHA_HTTP_STATUS_CODE not supported, using default", {http_status_code = http_status_code, default_code = DEFAULT_RET_CODE})
    return DEFAULT_RET_CODE
end

local function table_to_encoded_url(args)
    local params = {}
    for k, v in pairs(args) do
        if v then -- Only include non-nil values
            table.insert(params, k .. '=' .. ngx.escape_uri(tostring(v)))
        end
    end
    return table.concat(params, "&")
end

-- Public functions
function captcha.new(site_key, secret_key, template_path, captcha_provider, http_status_code)
    -- Validate captcha provider
    local is_valid_provider, provider_error = validate_captcha_provider(captcha_provider)
    if not is_valid_provider then
        return provider_error
    end

    -- Validate required parameters
    local is_valid_params, param_error = validate_required_params(site_key, secret_key, template_path)
    if not is_valid_params then
        return param_error
    end

    -- Read and validate template
    local captcha_template = utils.read_file(template_path)
    if not captcha_template then
        return "Template file " .. template_path .. " not found or empty"
    end

    -- Update module state
    module_state.site_key = site_key
    module_state.secret_key = secret_key
    module_state.captcha_provider = captcha_provider
    module_state.ret_code = validate_http_code(http_status_code)

    -- Compile template
    local template_data = {
        captcha_site_key = module_state.site_key,
        captcha_frontend_js = CAPTCHA_PROVIDERS[captcha_provider].frontend_js,
        captcha_frontend_key = CAPTCHA_PROVIDERS[captcha_provider].frontend_key
    }

    local view = template.compile(captcha_template, template_data)
    if not view then
        return "Failed to compile captcha template"
    end

    module_state.template = view
    return nil
end

function captcha.apply()
    if not module_state.template or module_state.template == "" then
        logger.error("Captcha template not initialized")
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.say("Internal server error")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    ngx.header.content_type = "text/html"
    ngx.header.cache_control = "no-cache, no-store, must-revalidate"
    ngx.header.pragma = "no-cache"
    ngx.header.expires = "0"
    ngx.status = module_state.ret_code
    ngx.say(module_state.template)
    ngx.exit(module_state.ret_code)
end

function captcha.get_captcha_backend_key()
    if not module_state.captcha_provider then
        return nil
    end
    return CAPTCHA_PROVIDERS[module_state.captcha_provider].response_key
end

function captcha.validate(captcha_res, remote_ip)
    if not captcha_res or captcha_res == "" then
        return false, "No captcha response provided"
    end

    if not module_state.captcha_provider then
        return false, "Captcha provider not initialized"
    end

    local provider = CAPTCHA_PROVIDERS[module_state.captcha_provider]
    local body = {
        secret = module_state.secret_key,
        response = captcha_res,
        remoteip = remote_ip
    }

    local data = table_to_encoded_url(body)
    local httpc = http.new()

    -- Set timeout and make request
    httpc:set_timeout(HTTP_TIMEOUT)
    local res, err = httpc:request_uri(provider.backend_url, {
        method = "POST",
        body = data,
        headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded",
        },
    })
    httpc:close()

    -- Log request details (without sensitive data)
    logger.info("Captcha validation request", {
        provider = module_state.captcha_provider,
        response_length = #captcha_res,
        remote_ip = remote_ip or "unknown"
    })

    -- Handle HTTP errors
    if err then
        logger.error("Captcha validation HTTP error", {error = err})
        return false, "HTTP request failed: " .. err
    end

    if not res then
        logger.error("No HTTP response received from captcha service")
        return false, "No response from captcha service"
    end

    logger.info("Captcha validation HTTP response", {status = res.status})

    -- Handle non-200 responses
    if res.status ~= 200 then
        logger.error("Captcha service returned non-200 status", {status = res.status})
        return false, "Captcha service error: HTTP " .. res.status
    end

    if not res.body or res.body == "" then
        logger.error("Empty response body from captcha service")
        return false, "Empty response from captcha service"
    end

    -- Parse JSON response
    local success, result = pcall(cjson.decode, res.body)
    if not success then
        logger.error("Failed to parse captcha service response", {error = tostring(result)})
        return false, "Invalid response from captcha service"
    end

    if not result then
        logger.error("Nil result from captcha service response")
        return false, "Invalid response format from captcha service"
    end

    -- Check for success
    if result.success == true then
        return true, nil
    end

    -- Handle error codes
    if result["error-codes"] then
        for _, error_code in ipairs(result["error-codes"]) do
            if error_code == "invalid-input-secret" then
                logger.error("Captcha secret key is invalid")
                return false, "Invalid secret key"
            elseif error_code == "invalid-input-response" then
                logger.info("Invalid captcha response from user")
                return false, "Invalid captcha response"
            elseif error_code == "timeout-or-duplicate" then
                logger.info("Captcha response expired or duplicate")
                return false, "Captcha response expired"
            end
        end
    end

    logger.info("Captcha validation failed without specific error code")
    return false, "Captcha validation failed"
end

-- Getters for module state (useful for debugging/testing)
function captcha.get_site_key()
    return module_state.site_key
end

function captcha.get_provider()
    return module_state.captcha_provider
end

function captcha.get_http_status_code()
    return module_state.ret_code
end

return captcha
