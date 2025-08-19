# lua-resty-arxignis

## 🎉 Join Our Discord Community! 🎉

Come hang out with us and be part of our awesome community on Discord! Whether you're here to chat, get support, or just have fun, everyone is welcome.

[![Join us on Discord](https://img.shields.io/badge/Join%20Us%20on-Discord-5865F2?logo=discord&logoColor=white)](https://discord.gg/jzsW5Q6s9q)

See you there! 💬✨

A comprehensive integration package for OpenResty/nginx that provides Arxignis security features including captcha handling, logging, metrics collection, and remediation capabilities.

## Features

- **Captcha Integration**: Handle Arxignis captcha challenges
- **Logging**: Comprehensive logging and monitoring
- **Metrics Collection**: Performance and security metrics
- **Remediation**: Automated threat response and blocking
- **Worker Processes**: Background task processing
- **Caching**: High-performance caching with mlcache

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
env ARXIGNIS_CAPTCHA_SITE_KEY;
env ARXIGNIS_CAPTCHA_SECRET_KEY;
env ARXIGNIS_API_KEY;
env ARXIGNIS_API_URL;
env ARXIGNIS_CAPTCHA_PROVIDER;
env ARXIGNIS_MODE;
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

## Usage Example

Here's a complete nginx configuration example:

```nginx
#user  nobody;
worker_processes  1;

error_log  /var/log/nginx/error.log  debug;

events {
    worker_connections  1024;
}

env ARXIGNIS_CAPTCHA_SITE_KEY;
env ARXIGNIS_CAPTCHA_SECRET_KEY;
env ARXIGNIS_API_KEY;
env ARXIGNIS_API_URL;
env ARXIGNIS_CAPTCHA_PROVIDER;
env ARXIGNIS_MODE;

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
        ngx.log(ngx.DEBUG, "Starting flush timers " .. ngx.worker.id())
        worker.start_flush_timers({
            ARXIGNIS_API_URL = os.getenv("ARXIGNIS_API_URL"),
            ARXIGNIS_API_KEY = os.getenv("ARXIGNIS_API_KEY")
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
            arxignis.remediate(ngx.var.remote_addr)
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

-- Remediate threats
arxignis.remediate(ip_address)
```

### Captcha Module

```lua
local captcha = require "resty.arxignis.captcha"

-- Verify captcha response
local success = captcha.verify(response_token)
```

### Logger Module

```lua
local logger = require "resty.arxignis.logger"

-- Log security events
logger.log_event(event_type, data)
```

### Metrics Module

```lua
local metrics = require "resty.arxignis.metrics"

-- Record metrics
metrics.record(metric_name, value)
```

### Worker Module

```lua
local worker = require "resty.arxignis.worker"

-- Start background workers
worker.start_flush_timers(config)
```

## Docker Support

Use the provided `docker-compose.yaml` for easy development setup:

```bash
docker-compose up -d
```

## Testing

Run the test suite:

```bash
cd t
prove *.t
```

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
