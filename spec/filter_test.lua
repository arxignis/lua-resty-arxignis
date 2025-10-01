local resty_string = require("resty.string")

local filter_module = "resty.arxignis.filter"

local original_ngx = ngx

local function reset_module()
  package.loaded[filter_module] = nil
end

local function mock_ngx(overrides)
  local mock = {}
  if original_ngx then
    setmetatable(mock, { __index = original_ngx })
  end

  for key, value in pairs(overrides) do
    mock[key] = value
  end

  _G.ngx = mock
end

describe("resty.arxignis.filter", function()
  after_each(function()
    reset_module()
    _G.ngx = original_ngx
  end)

  it("sanitises base URL and applies defaults", function()
    mock_ngx({})

    local filter = require(filter_module)
    local client = filter.new({ api_url = "https://api.example.com//" })

    assert.same("https://api.example.com", client.api_url)
    assert.is_true(client.ssl_verify)
    assert.is_number(client.timeout)
  end)

  it("sends filter events with expected request parameters", function()
    local captured = {}

    local http_client = {
      set_timeout = function(_, value)
        captured.timeout = value
      end,
      request_uri = function(_, url, options)
        captured.url = url
        captured.options = options
        return {
          status = 201,
          body = "{\"success\":true}",
          headers = { ["content-type"] = "application/json" },
        }
      end,
    }

    mock_ngx({
      encode_args = function(args)
        return string.format("idempotency-key=%s&originalEvent=%s", args["idempotency-key"], args.originalEvent)
      end,
      log = function() end,
      WARN = "warn",
      ERR = "err",
    })

    local filter = require(filter_module)

    local client = filter.new({
      api_url = "https://api.example.com/",
      api_key = "secret",
      timeout = 1500,
      ssl_verify = false,
      http_client_factory = function()
        return http_client
      end,
    })

    local event = { event_type = "filter" }
    local response, err = client:send(event, {
      idempotency_key = "abc123",
      original_event = true,
      headers = { ["X-Test"] = "1" },
    })

    assert.is_nil(err)
    assert.same("https://api.example.com/filter?idempotency-key=abc123&originalEvent=true", captured.url)
    assert.same(1500, captured.timeout)
    assert.same("Bearer secret", captured.options.headers.Authorization)
    assert.same("1", captured.options.headers["X-Test"])
    assert.is_false(captured.options.ssl_verify)
    assert.same(201, response.status)
    assert.is_table(response.json)
    assert.is_true(response.json.success)
  end)

  it("builds event from request context", function()
    local body = "{\"username\":\"john\"}"
    local expected_hash = resty_string.to_hex(body)
    local expected_query_hash = resty_string.to_hex("foo=bar")

    mock_ngx({
      req = {
        read_body = function() return true end,
        get_body_data = function() return body end,
        get_body_file = function() return nil end,
        get_headers = function()
          return {
            ["content-type"] = "application/json",
            ["content-length"] = tostring(#body),
            ["host"] = "example.com",
            ["user-agent"] = "Mozilla/5.0",
          }
        end,
        get_method = function() return "POST" end,
      },
      var = {
        uri = "/api/v1/users",
        args = "foo=bar",
        scheme = "https",
        host = "example.com",
        remote_addr = "203.0.113.10",
        server_port = "443",
        request_id = "req-123",
      },
      sha256_bin = function(value)
        return value
      end,
      utctime = function()
        return "2025-01-15T10:30:00Z"
      end,
      encode_args = function(args)
        return string.format("idempotency-key=%s", args["idempotency-key"])
      end,
      log = function() end,
      WARN = "warn",
      ERR = "err",
    })

    local filter = require(filter_module)
    local event, err = filter.build_event_from_request({
      tenant_id = "tenant-1",
      additional = { source = "ingress" },
    })

    assert.is_nil(err)
    assert.same("filter", event.event_type)
    assert.same("1.0", event.schema_version)
    assert.same("req-123", event.request_id)
    assert.same("tenant-1", event.tenant_id)
    assert.is_table(event.additional)
    assert.same("ingress", event.additional.source)

    local http_section = event.http
    assert.same("POST", http_section.method)
    assert.same("/api/v1/users", http_section.path)
    assert.same("foo=bar", http_section.query)
    assert.same("example.com", http_section.host)
    assert.same("https", http_section.scheme)
    assert.same(443, http_section.port)
    assert.same("203.0.113.10", http_section.remote_ip)
    assert.same("Mozilla/5.0", http_section.user_agent)
    assert.same("application/json", http_section.content_type)
    assert.same(body, http_section.body)
    assert.same(expected_hash, http_section.body_sha256)
    assert.same(#body, http_section.content_length)
    assert.same(expected_query_hash, http_section.query_hash)
  end)
end)
