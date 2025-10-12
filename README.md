# lua-resty-arxignis

## 🎉 Join Our Discord Community! 🎉

Come hang out with us and be part of our awesome community on Discord! Whether you're here to chat, get support, or just have fun, everyone is welcome.

[![Join us on Discord](https://img.shields.io/badge/Join%20Us%20on-Discord-5865F2?logo=discord&logoColor=white)](https://discord.gg/jzsW5Q6s9q)

See you there! 💬✨

A comprehensive integration package for OpenResty/nginx that provides Arxignis security features including threat intelligence, captcha handling, WAF protection, content scanning, logging, metrics collection, and remediation capabilities.

**Current Version**: 1.5-2

## Features

- **Threat Intelligence**: Real-time IP threat analysis and scoring
- **Captcha Integration**: Multi-provider captcha support (reCAPTCHA, hCaptcha, Cloudflare Turnstile)
- **WAF Protection**: Web Application Firewall with content filtering
- **Content Scanning**: Malware detection and file scanning
- **Access Rules**: IP-based access control with country/ASN filtering
- **Secure Token Management**: Cryptographically secure captcha tokens with IP/User-Agent binding
- **Comprehensive Logging**: Structured logging with configurable levels
- **Metrics Collection**: Performance and security metrics tracking
- **Background Workers**: Asynchronous log processing and API communication
- **Caching**: High-performance caching with shared memory dictionaries
- **Monitor/Block Modes**: Flexible enforcement modes for testing and production

## Security Features

### Threat Intelligence
- Real-time IP reputation scoring
- Malware and botnet detection
- Geographic and ASN-based analysis
- Confidence scoring and threat categorization

### Captcha Providers
The library supports multiple captcha providers:

- **hCaptcha**: Privacy-focused captcha service
- **reCAPTCHA**: Google's captcha service
- **Cloudflare Turnstile**: Cloudflare's privacy-preserving captcha

### Secure Token Management
- Cryptographically secure captcha tokens
- IP address and User-Agent binding
- JA4 fingerprint integration for SSL/TLS requests
- 2-hour token expiration with automatic renewal

### Content Protection
- Web Application Firewall (WAF) with rule-based filtering
- Malware scanning for uploaded files
- Content analysis and threat detection
- Real-time blocking and remediation

## Installation

### Using LuaRocks

```bash
luarocks install lua-resty-arxignis
```

### Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/arxignis/lua-resty-arxignis.git
cd lua-resty-arxignis
```

2. Copy the library files to your OpenResty installation:
```bash
cp -r lib/resty/arxignis /usr/local/openresty/lualib/resty/
```

## Dependencies

- Lua >= 5.1
- lua-resty-core >= 0.1.0
- lua-resty-http >= 0.17.2
- lua-resty-mlcache >= 2.6.0
- lua-resty-jwt >= 0.2.3
- lua-resty-cookie >= 0.4.1

## Configuration

### Environment Variables

Set the following environment variables in your nginx configuration:

```nginx
env ARXIGNIS_API_URL;
env ARXIGNIS_API_KEY;
env ARXIGNIS_CAPTCHA_SITE_KEY;
env ARXIGNIS_CAPTCHA_SECRET_KEY;
env ARXIGNIS_CAPTCHA_PROVIDER;
env ARXIGNIS_MODE;
env ARXIGNIS_ACCESS_RULE_ID;  # optional
```

### Shared Memory

Configure shared memory dictionaries for caching and queuing:

```nginx
lua_shared_dict arxignis_cache 200m;
lua_shared_dict arxignis_queue 50m;
```

### SSL Configuration

Ensure proper SSL certificate handling:

```nginx
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
```

## Configuration

The library uses a centralized configuration system to manage environment variables and settings. All configuration is handled through the `resty.arxignis.config` module.

### Environment Variables

The following environment variables are required:

```bash
ARXIGNIS_API_URL=https://api.arxignis.com/v1
ARXIGNIS_API_KEY=your_api_key_here
ARXIGNIS_CAPTCHA_SITE_KEY=your_captcha_site_key
ARXIGNIS_CAPTCHA_SECRET_KEY=your_captcha_secret_key
ARXIGNIS_CAPTCHA_PROVIDER=hcaptcha  # or "recaptcha" or "turnstile"
ARXIGNIS_MODE=monitor  # or "block"
ARXIGNIS_ACCESS_RULE_ID=your_access_rule_id  # optional
```

### Using the Configuration Module

```lua
local config = require("resty.arxignis.config")

-- Get individual configuration values
local api_url = config.get_api_url()
local api_key = config.get_api_key()
local mode = config.get_mode()

-- Get all configuration as a table
local env = config.get_env()

-- Validate configuration
local is_valid, missing_vars = config.validate()
if not is_valid then
    ngx.log(ngx.ERR, "Missing required variables: " .. table.concat(missing_vars, ", "))
end
```

### Configuration Features

- **Centralized Management**: All environment variables are managed in one place
- **Validation**: Built-in validation for required configuration
- **Caching**: Configuration is cached in shared memory for performance
- **Fallbacks**: Sensible defaults and fallback values where appropriate
- **Backward Compatibility**: Existing code continues to work without changes

## Usage Example

Here's a complete nginx configuration example:

```nginx
#user  nobody;
worker_processes  1;

error_log  /var/log/nginx/error.log  debug;

events {
    worker_connections  1024;
}

env ARXIGNIS_API_URL;
env ARXIGNIS_API_KEY;
env ARXIGNIS_CAPTCHA_SITE_KEY;
env ARXIGNIS_CAPTCHA_SECRET_KEY;
env ARXIGNIS_CAPTCHA_PROVIDER;
env ARXIGNIS_MODE;
env ARXIGNIS_ACCESS_RULE_ID;
http {
    include       mime.types;
    default_type  application/octet-stream;
    resolver 127.0.0.11 ipv6=off;
    lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
    lua_shared_dict arxignis_cache 200m;
    lua_shared_dict arxignis_queue 50m;
    lua_code_cache off;

    # Initialize cache in init_by_lua_block
    init_by_lua_block {
        local mlcache = require "resty.mlcache"
        local arxignis_cache, err = mlcache.new("arxignis_cache", "arxignis_cache", {
            lru_size = 50000,
            ttl = 800,
            neg_ttl = 10,
        })
        if err then
            -- Handle error
        end

        _G.arxignis_cache = arxignis_cache
    }

    # Start worker processes in init_worker_by_lua_block
    init_worker_by_lua_block {
        local worker = require "resty.arxignis.worker"
        local config = require "resty.arxignis.config"
        ngx.log(ngx.DEBUG, "Starting flush timers " .. ngx.worker.id())
        worker.start_flush_timers({
            ARXIGNIS_API_URL = config.get_api_url(),
            ARXIGNIS_API_KEY = config.get_api_key()
        })
    }

    sendfile        on;
    keepalive_timeout  65;

    server {
        listen       80;
        server_name  _;

        # Apply Arxignis remediation on every request
        access_by_lua_block {
            local arxignis = require "resty.arxignis"
            -- Pass IP address, country, and ASN for comprehensive analysis
            arxignis.remediate(ngx.var.remote_addr, ngx.var.geoip_country_code, ngx.var.geoip_asn)
        }

        location / {
            content_by_lua_block {
                ngx.header.content_type = "text/html"
                ngx.say("Hello, World!")
                ngx.exit(ngx.HTTP_OK)
            }
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }
}
```

## API Reference

### Core Module

```lua
local arxignis = require "resty.arxignis"

-- Main remediation function - analyzes threats and applies security measures
arxignis.remediate(ip_address, country, asn)
```

### Configuration Module

```lua
local config = require "resty.arxignis.config"

-- Get individual configuration values
local api_url = config.get_api_url()
local api_key = config.get_api_key()
local mode = config.get_mode()
local captcha_provider = config.get_captcha_provider()

-- Get all configuration as a table
local env = config.get_env()

-- Validate configuration
local is_valid, missing_vars = config.validate()
if not is_valid then
    ngx.log(ngx.ERR, "Missing required variables: " .. table.concat(missing_vars, ", "))
end

-- Store configuration in shared cache
config.store_in_cache()
```

### Captcha Module

```lua
local captcha = require "resty.arxignis.captcha"

-- Initialize captcha with provider-specific settings
local err = captcha.new(site_key, secret_key, template_path, provider, ret_code)

-- Validate captcha response
local is_valid, error_msg = captcha.validate(response_token, ip_address)

-- Apply captcha challenge (show captcha form)
captcha.apply()
```

### Threat Intelligence Module

```lua
local threat = require "resty.arxignis.threat"

-- Get threat intelligence for an IP address
local threat_data = threat.get(ip_address, mode)
-- Returns: { intel = {...}, advice = "allow|block|challenge", ... }
```

### Access Rules Module

```lua
local access_rules = require "resty.arxignis.access_rules"

-- Check access rules for an IP address
local rules = access_rules.check(ip_address, country, asn)
-- Returns: { access_rules = { action = "allow|block" } }
```

### Filter Module (WAF)

```lua
local filter = require "resty.arxignis.filter"

-- Create filter client
local filter_client = filter.new({
    api_url = "https://api.arxignis.com/v1",
    api_key = "your_api_key",
    ssl_verify = true
})

-- Build event from current request
local event = filter.build_event_from_request({
    tenant_id = "optional_tenant_id",
    additional = { custom_data = "value" }
})

-- Send filter request
local response, err = filter_client:send(event, { original_event = false })

-- Build and send content scan request
local scan_request = filter.build_scan_request_from_event(event)
local scan_response, scan_err = filter_client:scan(scan_request)
```

### Logger Module

```lua
local logger = require "resty.arxignis.logger"

-- Set log level
logger.set_level("debug")  -- emerg, alert, crit, error, warn, notice, info, debug

-- Log messages with structured data
logger.info("Request processed", { ip_address = "1.2.3.4", action = "allowed" })
logger.warn("Suspicious activity detected", { threat_score = 85 })
logger.error("API request failed", { error = "connection timeout" })
logger.debug("Debug information", { request_id = "abc123" })
```

### Worker Module

```lua
local worker = require "resty.arxignis.worker"

-- Start background workers for log processing
worker.start_flush_timers({
    ARXIGNIS_API_URL = "https://api.arxignis.com/v1",
    ARXIGNIS_API_KEY = "your_api_key"
})
```

### Metrics Module

```lua
local metrics = require "resty.arxignis.metrics"

-- Record custom metrics
metrics.record("requests_total", 1)
metrics.record("threat_score", threat_score)
metrics.record("response_time", response_time_ms)
```

## Docker Support

Use the provided `docker-compose.yaml` for easy development setup:

```bash
docker-compose up -d
```

## Testing

Run the test suite using the provided test scripts:

```bash
# Run Lua tests
./test/test-lua.sh

# Run packaging tests
./test-packaging.sh

# Run HTML packaging tests
./test-html-packaging.sh
```

The test suite includes:
- Unit tests for individual modules
- Integration tests for the complete workflow
- Template rendering tests
- Packaging and distribution tests

## License

Apache License 2.0

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Support

For support and questions, please open an issue on GitHub or contact the Arxignis team.
