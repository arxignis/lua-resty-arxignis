local config = {_TYPE='module', _NAME='arxignis.config', _VERSION='1.0-0'}

-- Centralized configuration for Arxignis API settings
local _config = {
    api_url = "https://api.arxignis.com/v1",
    api_key = nil,
    captcha_site_key = nil,
    captcha_secret_key = nil,
    captcha_provider = nil,
    mode = "monitor",
    access_rule_id = nil,
    initialized = false
}

-- Initialize configuration from environment variables
function config.init()
    if _config.initialized then
        return _config
    end

    _config.api_url = os.getenv("ARXIGNIS_API_URL")
    _config.api_key = os.getenv("ARXIGNIS_API_KEY")
    _config.captcha_site_key = os.getenv("ARXIGNIS_CAPTCHA_SITE_KEY")
    _config.captcha_secret_key = os.getenv("ARXIGNIS_CAPTCHA_SECRET_KEY")
    _config.captcha_provider = os.getenv("ARXIGNIS_CAPTCHA_PROVIDER")
    _config.mode = os.getenv("ARXIGNIS_MODE")
    _config.access_rule_id = os.getenv("ARXIGNIS_ACCESS_RULE_ID")

    _config.initialized = true

    return _config
end

-- Get API URL with fallback
function config.get_api_url()
    config.init()
    return _config.api_url
end

-- Get API key
function config.get_api_key()
    config.init()
    return _config.api_key
end

-- Get captcha site key
function config.get_captcha_site_key()
    config.init()
    return _config.captcha_site_key
end

-- Get captcha secret key
function config.get_captcha_secret_key()
    config.init()
    return _config.captcha_secret_key
end

-- Get captcha provider
function config.get_captcha_provider()
    config.init()
    return _config.captcha_provider
end

-- Get mode with default fallback
function config.get_mode()
    config.init()
    if _config.mode ~= "block" then
        return "monitor"
    end
    return _config.mode
end

-- Get access rule ID
function config.get_access_rule_id()
    config.init()
    return _config.access_rule_id
end

-- Get all configuration as a table (for backward compatibility)
function config.get_env()
    config.init()
    return {
        ARXIGNIS_API_URL = _config.api_url,
        ARXIGNIS_API_KEY = _config.api_key,
        ARXIGNIS_CAPTCHA_SITE_KEY = _config.captcha_site_key,
        ARXIGNIS_CAPTCHA_SECRET_KEY = _config.captcha_secret_key,
        ARXIGNIS_CAPTCHA_PROVIDER = _config.captcha_provider,
        ARXIGNIS_MODE = _config.mode,
        ARXIGNIS_ACCESS_RULE_ID = _config.access_rule_id
    }
end

-- Validate required configuration
function config.validate()
    config.init()

    local required_vars = {
        "ARXIGNIS_API_KEY",
        "ARXIGNIS_CAPTCHA_SECRET_KEY",
        "ARXIGNIS_CAPTCHA_SITE_KEY",
        "ARXIGNIS_CAPTCHA_PROVIDER"
    }

    local missing_vars = {}

    for _, var_name in ipairs(required_vars) do
        local value = _config[string.lower(string.gsub(var_name, "ARXIGNIS_", ""))]
        if not value or value == "" then
            table.insert(missing_vars, var_name)
        end
    end

    return #missing_vars == 0, missing_vars
end

-- Store configuration in shared cache for performance
function config.store_in_cache()
    config.init()

    local cache = ngx.shared.arxignis_cache
    if not cache then
        return false
    end

    for key, value in pairs(_config) do
        if value and key ~= "initialized" then
            cache:set("config_" .. key, value)
        end
    end

    return true
end

-- Load configuration from shared cache
function config.load_from_cache()
    local cache = ngx.shared.arxignis_cache
    if not cache then
        return false
    end

    _config.api_url = cache:get("config_api_url") or _config.api_url
    _config.api_key = cache:get("config_api_key") or _config.api_key
    _config.captcha_site_key = cache:get("config_captcha_site_key") or _config.captcha_site_key
    _config.captcha_secret_key = cache:get("config_captcha_secret_key") or _config.captcha_secret_key
    _config.captcha_provider = cache:get("config_captcha_provider") or _config.captcha_provider
    _config.mode = cache:get("config_mode") or _config.mode
    _config.access_rule_id = cache:get("config_access_rule_id") or _config.access_rule_id

    return true
end

return config
