local cjson = require("cjson.safe")

local worker_module = "resty.arxignis.worker"
local original_ngx = ngx

local function reset_module()
  package.loaded[worker_module] = nil
end

local function new_fake_dict()
  local storage = {}

  return {
    data = storage,
    get = function(self, key)
      return storage[key]
    end,
    set = function(self, key, value)
      storage[key] = value
      return true
    end,
    add = function(self, key, value)
      if storage[key] ~= nil then
        return nil, "exists"
      end
      storage[key] = value
      return true
    end,
  }
end

local function mock_ngx(opts)
  opts = opts or {}
  local mock = {}

  mock.shared = opts.shared or {}
  mock.log = opts.log or function() end
  mock.WARN = "warn"
  mock.ERR = "err"
  mock.DEBUG = "debug"
  mock.timer = opts.timer or {
    at = function(_, _, _)
      return true
    end,
  }

  if original_ngx then
    setmetatable(mock, { __index = original_ngx })
  end

  _G.ngx = mock
end

describe("resty.arxignis.worker", function()
  after_each(function()
    reset_module()
    _G.ngx = original_ngx
  end)

  it("enqueues filter events into shared queue", function()
    local dict = new_fake_dict()
    mock_ngx({ shared = { arxignis_queue = dict } })

    local worker = require(worker_module)
    local env = { ARXIGNIS_API_URL = "https://api.example.com" }

    local ok, err = worker.enqueue_filter_event(env, { id = 1 }, { idempotency_key = "key-1" })
    assert.is_true(ok)
    assert.is_nil(err)

    local queue = cjson.decode(dict:get("current_filter_queue"))
    assert.same(1, #queue)
    assert.same(1, queue[1].event.id)
    assert.same("key-1", queue[1].opts.idempotency_key)
  end)

  it("flushes filter queue via helper", function()
    local dict = new_fake_dict()
    mock_ngx({ shared = { arxignis_queue = dict }, timer = { at = function() return true end } })

    local sent = {}
    _G.require = require

    local worker = require(worker_module)

    dict:set("current_filter_queue", cjson.encode({
      { event = { id = 1 }, opts = { idempotency_key = "a" } },
      { event = { id = 2 }, opts = { idempotency_key = "b" } },
    }))

    local client = {
      send = function(_, event, opts)
        table.insert(sent, { event = event, opts = opts })
        return true
      end,
    }

    -- build_filter_client isn't exposed; stub constructor to return custom client
    local filter_module = require("resty.arxignis.filter")
    local original_new = filter_module.new
    filter_module.new = function()
      return client
    end

    local env = { ARXIGNIS_API_URL = "https://api.example.com" }
    worker.enqueue_filter_event(env, { id = 3 }, { idempotency_key = "c" })

    worker.flush_remaining_filters(env)

    assert.same(3, #sent)
    assert.equal("", dict:get("current_filter_queue"))

    filter_module.new = original_new
  end)

  it("requeues remaining filter events on failure", function()
    local dict = new_fake_dict()
    mock_ngx({ shared = { arxignis_queue = dict }, timer = { at = function() return true end } })

    dict:set("current_filter_queue", cjson.encode({
      { event = { id = 1 }, opts = { idempotency_key = "a" } },
      { event = { id = 2 }, opts = { idempotency_key = "b" } },
    }))

    local attempts = 0
    local filter_module = require("resty.arxignis.filter")
    local original_new = filter_module.new
    filter_module.new = function()
      return {
        send = function()
          attempts = attempts + 1
          if attempts == 1 then
            return nil, "boom"
          end
          return true
        end,
      }
    end

    local worker = require(worker_module)
    worker.flush_remaining_filters({ ARXIGNIS_API_URL = "https://api.example.com" })

    local queue = dict:get("current_filter_queue")
    assert.is_not_nil(queue)
    local decoded = cjson.decode(queue)
    assert.same(2, #decoded)
    assert.same(1, decoded[1].event.id)

    filter_module.new = original_new
  end)
end)
