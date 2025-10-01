local cjson = require "cjson"
local utils = require "resty.arxignis.utils"
local filter_module = require "resty.arxignis.filter"

local worker = {_TYPE='module', _NAME='arxignis.worker', _VERSION='1.0-0'}

-- Version constant
local VERSION = '0.0.1'

-- API global URL
local API_GLOBAL_URL = 'https://api.arxignis.com/v1'

-- Shared memory configuration
local SHARED_DICT_NAME = "arxignis_queue"
local BATCH_SIZE = 100
local FLUSH_INTERVAL = 5  -- seconds
local FILTER_QUEUE_KEY = "current_filter_queue"
local FILTER_BATCH_SIZE = 20

local function get_lock(lock_key, interval)
    local dict = ngx.shared.arxignis_queue
    local key = "l:" .. lock_key

    -- the lock is held for the whole interval to prevent multiple
    -- worker processes from sending the batch request simultaneously.
    -- here we substract the lock expiration time by 1ms to prevent
    -- a race condition with the next timer event use lock
    local ok, err = dict:add(key, true, interval - 0.001)
    if not ok then
        if err == "exists" then
            ngx.log(ngx.DEBUG, "Lock already exists for key: " .. key)
            return nil
        end
        error("failed to add key \"" .. key .. "\": " .. err)
        return nil
    end
    ngx.log(ngx.DEBUG, "Lock acquired for key: " .. key)
    return true
end

local function make_batch_api_request(env, entries, endpoint)
    local api_url = env.ARXIGNIS_API_URL or API_GLOBAL_URL
    local url = api_url .. endpoint

    ngx.log(ngx.DEBUG, "Making batch API request to: " .. url .. " with " .. #entries .. " entries")

    local headers = {
        ['Accept'] = 'application/json',
        ['Content-Type'] = 'application/json'
    }

    if env.ARXIGNIS_API_KEY then
        headers['Authorization'] = 'Bearer ' .. env.ARXIGNIS_API_KEY
        ngx.log(ngx.DEBUG, "Using API key for authentication")
    else
        ngx.log(ngx.WARN, "No API key provided, request will be unauthenticated")
    end

    local batch_payload = {
        entries = entries
    }

    ngx.log(ngx.DEBUG, "Sending batch payload: " .. cjson.encode(batch_payload))

    local res, err = utils.http_request(url, {
        method = 'POST',
        timeout = 30000,
        headers = headers,
        body = cjson.encode(batch_payload),
        ssl_verify = true
    })

    if err then
        ngx.log(ngx.ERR, "Batch API request failed: " .. (err or "unknown error"))
    elseif res and res.status ~= 200 then
        ngx.log(ngx.ERR, "Batch API request failed with status " .. (res.status or "unknown") .. ": " .. (res.body or ""))
    else
        ngx.log(ngx.DEBUG, "Batch API request successful, status: " .. (res.status or "unknown"))
    end
end

local function decode_queue(dict, key)
    local raw = dict:get(key)
    if not raw or raw == '' then
        return {}
    end

    local ok, value = pcall(cjson.decode, raw)
    if not ok or type(value) ~= 'table' then
        ngx.log(ngx.WARN, "Arxignis worker: failed to decode queue for key " .. key .. ": " .. (value or 'unknown'))
        dict:set(key, '')
        return {}
    end

    return value
end

local function encode_queue(dict, key, queue)
    if not queue or #queue == 0 then
        dict:set(key, '')
        return true
    end

    local ok, encoded = pcall(cjson.encode, queue)
    if not ok then
        ngx.log(ngx.ERR, "Arxignis worker: failed to encode queue for key " .. key .. ": " .. (encoded or 'unknown'))
        return false
    end

    dict:set(key, encoded)
    return true
end

local function build_filter_client(env, overrides)
    overrides = overrides or {}
    return filter_module.new({
        api_url = overrides.api_url or env.ARXIGNIS_API_URL,
        api_key = overrides.api_key or env.ARXIGNIS_API_KEY,
        timeout = overrides.timeout,
        ssl_verify = overrides.ssl_verify,
        http_client_factory = overrides.http_client_factory,
    })
end

function worker.enqueue_filter_event(env, event, opts)
    opts = opts or {}

    if type(event) ~= 'table' then
        ngx.log(ngx.ERR, 'Arxignis worker: expected event table but received ' .. type(event))
        return nil, 'event must be a table'
    end

    local dict = ngx.shared[SHARED_DICT_NAME]
    if not dict then
        ngx.log(ngx.ERR, "Shared dict '" .. SHARED_DICT_NAME .. "' not found")
        return nil, 'shared dict not available'
    end

    local queue = decode_queue(dict, FILTER_QUEUE_KEY)
    queue[#queue + 1] = {
        event = event,
        opts = opts,
    }

    encode_queue(dict, FILTER_QUEUE_KEY, queue)

    if #queue >= FILTER_BATCH_SIZE then
        ngx.log(ngx.DEBUG, 'Arxignis worker: filter queue reached ' .. #queue .. ' entries, flushing early')
        process_filter_queue(env, dict)
    end

    return true
end

local function process_filter_queue(env, dict)
    local queue = decode_queue(dict, FILTER_QUEUE_KEY)
    if #queue == 0 then
        return
    end

    local client = build_filter_client(env)
    local success_count = 0
    local remaining = nil

    for idx, item in ipairs(queue) do
        local result, err = client:send(item.event, item.opts)
        if not result then
            ngx.log(ngx.ERR, "Arxignis worker: filter send failed: " .. (err or 'unknown error'))
            remaining = {}
            for j = idx, #queue do
                table.insert(remaining, queue[j])
            end
            break
        end
        success_count = success_count + 1
    end

    if remaining then
        encode_queue(dict, FILTER_QUEUE_KEY, remaining)
    else
        dict:set(FILTER_QUEUE_KEY, '')
    end

    ngx.log(ngx.DEBUG, "Arxignis worker: processed " .. success_count .. " filter events")
end


function worker.add_log_to_batch(env, log_entry)
    local dict = ngx.shared[SHARED_DICT_NAME]
    if not dict then
        ngx.log(ngx.ERR, "Shared dict 'arxignis_queue' not found")
        return
    end

    -- Validate log entry before processing
    if not log_entry or type(log_entry) ~= "table" then
        ngx.log(ngx.ERR, "Invalid log entry: expected table, got " .. type(log_entry))
        return
    end

    -- Get current batch from shared memory
    local batch_key = "current_batch"
    local batch_data = dict:get(batch_key)
    local batch = {}


    if batch_data and #batch_data > 0 then
        local success, decoded = pcall(cjson.decode, batch_data)
        if success then
            batch = decoded
            ngx.log(ngx.DEBUG, "Loaded existing batch with " .. #batch .. " logs")
        else
            ngx.log(ngx.WARN, "Failed to decode existing batch, starting fresh" .. (cjson.encode(batch_data) or "nil"))
            -- Clear the corrupted data
            dict:set(batch_key, "")
            ngx.log(ngx.DEBUG, "Cleared corrupted batch data from shared memory")
        end
    else
        ngx.log(ngx.DEBUG, "No existing batch found, starting fresh")
    end

    -- Add new log entry
    table.insert(batch, log_entry)
    ngx.log(ngx.DEBUG, "Added log entry to batch, total logs: " .. #batch)

    -- Check if batch is full or if we need to flush
    local should_flush = #batch >= BATCH_SIZE

    if should_flush then
        -- Send batch immediately
        ngx.log(ngx.DEBUG, "Batch full (" .. #batch .. " logs), flushing immediately")
        make_batch_api_request(env, batch, "/log/batch")
        -- Clear batch
        dict:set(batch_key, "")
        ngx.log(ngx.DEBUG, "Flushed batch of " .. #batch .. " logs")
    else
        -- Store updated batch with error handling
        local success, batch_json = pcall(cjson.encode, batch)
        if success then
            dict:set(batch_key, batch_json)
            ngx.log(ngx.DEBUG, "Stored batch with " .. #batch .. " logs in shared memory")
        else
            ngx.log(ngx.ERR, "Failed to encode batch for storage: " .. (batch_json or "unknown error"))
            -- Clear the corrupted batch and start fresh
            dict:set(batch_key, "")
            ngx.log(ngx.WARN, "Cleared corrupted batch, will start fresh on next log entry")
        end
    end
end

function worker.add_metrics_to_batch(env, metrics_entry)
    local dict = ngx.shared[SHARED_DICT_NAME]
    if not dict then
        ngx.log(ngx.ERR, "Shared dict 'arxignis_queue' not found")
        return
    end

    -- Validate metrics entry before processing
    if not metrics_entry or type(metrics_entry) ~= "table" then
        ngx.log(ngx.ERR, "Invalid metrics entry: expected table, got " .. type(metrics_entry))
        return
    end

    -- Get current batch from shared memory
    local batch_key = "current_metrics_batch"
    local batch_data = dict:get(batch_key)
    local batch = {}

    if batch_data and #batch_data > 0 then
        local success, decoded = pcall(cjson.decode, batch_data)
        if success then
            batch = decoded
            ngx.log(ngx.DEBUG, "Loaded existing metrics batch with " .. #batch .. " entries")
        else
            ngx.log(ngx.WARN, "Failed to decode existing metrics batch, starting fresh" .. (cjson.encode(batch_data) or "nil"))
            -- Clear the corrupted data
            dict:set(batch_key, "")
            ngx.log(ngx.DEBUG, "Cleared corrupted metrics batch data from shared memory")
        end
    else
        ngx.log(ngx.DEBUG, "No existing metrics batch found, starting fresh")
    end

    -- Add new metrics entry
    table.insert(batch, metrics_entry)
    ngx.log(ngx.DEBUG, "Added metrics entry to batch, total entries: " .. #batch)

    -- Check if batch is full or if we need to flush
    local should_flush = #batch >= BATCH_SIZE

    if should_flush then
        -- Send batch immediately
        ngx.log(ngx.DEBUG, "Metrics batch full (" .. #batch .. " entries), flushing immediately")
        make_batch_api_request(env, batch, "/metrics/batch")
        -- Clear batch
        dict:set(batch_key, "")
        ngx.log(ngx.DEBUG, "Flushed metrics batch of " .. #batch .. " entries")
    else
        -- Store updated batch with error handling
        local success, batch_json = pcall(cjson.encode, batch)
        if success then
            dict:set(batch_key, batch_json)
            ngx.log(ngx.DEBUG, "Stored metrics batch with " .. #batch .. " entries in shared memory")
        else
            ngx.log(ngx.ERR, "Failed to encode metrics batch for storage: " .. (batch_json or "unknown error"))
            -- Clear the corrupted batch and start fresh
            dict:set(batch_key, "")
            ngx.log(ngx.WARN, "Cleared corrupted metrics batch, will start fresh on next entry")
        end
    end
end

local function flush_filter_timer(premature, env)
    if premature then
        ngx.log(ngx.DEBUG, 'Arxignis filter flush timer firing prematurely, exiting')
        return
    end

    local dict = ngx.shared[SHARED_DICT_NAME]
    if not dict then
        ngx.log(ngx.ERR, "Shared dict '" .. SHARED_DICT_NAME .. "' not found, cannot flush filter queue")
        return
    end

    local lock_acquired = get_lock('arxignis_filter_flush', FLUSH_INTERVAL)
    if not lock_acquired then
        ngx.log(ngx.DEBUG, 'Arxignis filter flush skipped, another worker holds the lock')
        return
    end

    process_filter_queue(env, dict)

    local ok, err = ngx.timer.at(FLUSH_INTERVAL, flush_filter_timer, env)
    if not ok then
        ngx.log(ngx.ERR, "Failed to reschedule filter flush timer: " .. (err or "unknown error"))
    end
end


-- Timer callback function to flush logs
local function flush_logs_timer(premature, env)
    ngx.log(ngx.DEBUG, "Timer callback executed for worker " .. ngx.worker.id() .. " at " .. os.date())

    if premature then
        ngx.log(ngx.DEBUG, "Timer was premature, exiting")
        return
    end

    -- Check if shared dictionary exists
    local dict = ngx.shared[SHARED_DICT_NAME]
    if not dict then
        ngx.log(ngx.ERR, "Shared dict '" .. SHARED_DICT_NAME .. "' not found, cannot flush logs")
        -- Still reschedule the timer even if we can't flush
        ngx.log(ngx.DEBUG, "Rescheduling timer for worker " .. ngx.worker.id() .. " in " .. FLUSH_INTERVAL .. " seconds")
        local ok, err = ngx.timer.at(FLUSH_INTERVAL, flush_logs_timer, env)
        if not ok then
            ngx.log(ngx.ERR, "Failed to reschedule flush timer: " .. (err or "unknown error"))
        else
            ngx.log(ngx.DEBUG, "Timer rescheduled successfully for worker " .. ngx.worker.id())
        end
        return
    end

    -- Try to acquire lock to prevent multiple workers from flushing simultaneously
    local lock_acquired = get_lock("arxignis_flush", FLUSH_INTERVAL)
    if lock_acquired then
        local batch_key = "current_batch"
        local batch_data = dict:get(batch_key)

        ngx.log(ngx.DEBUG, "Lock acquired, checking batch data. Raw data: " .. (batch_data or "nil"))

        if batch_data and batch_data ~= "" then
            local success, batch = pcall(cjson.decode, batch_data)
            if success and #batch > 0 then
                ngx.log(ngx.DEBUG, "Found " .. #batch .. " logs to flush, sending to API")
                make_batch_api_request(env, batch, "/log/batch")
                dict:set(batch_key, "")
                ngx.log(ngx.DEBUG, "Timer flushed " .. #batch .. " logs from worker " .. ngx.worker.id())
            else
                ngx.log(ngx.DEBUG, "Batch decode failed or empty batch. Success: " .. tostring(success) .. ", batch size: " .. (#batch or 0))
            end
        else
            ngx.log(ngx.DEBUG, "No batch data found to flush")
        end
    else
        ngx.log(ngx.DEBUG, "Lock not acquired, skipping flush but timer will continue")
    end

    -- Reschedule the timer for the next interval
    ngx.log(ngx.DEBUG, "Rescheduling timer for worker " .. ngx.worker.id() .. " in " .. FLUSH_INTERVAL .. " seconds")
    local ok, err = ngx.timer.at(FLUSH_INTERVAL, flush_logs_timer, env)
    if not ok then
        ngx.log(ngx.ERR, "Failed to reschedule flush timer: " .. (err or "unknown error"))
    else
       ngx.log(ngx.DEBUG, "Timer rescheduled successfully for worker " .. ngx.worker.id())
    end
end

-- Timer callback function to flush metrics
local function flush_metrics_timer(premature, env)
    ngx.log(ngx.DEBUG, "Metrics timer callback executed for worker " .. ngx.worker.id() .. " at " .. os.date())

    if premature then
        ngx.log(ngx.DEBUG, "Metrics timer was premature, exiting")
        return
    end

    -- Check if shared dictionary exists
    local dict = ngx.shared[SHARED_DICT_NAME]
    if not dict then
        ngx.log(ngx.ERR, "Shared dict '" .. SHARED_DICT_NAME .. "' not found, cannot flush metrics")
        -- Still reschedule the timer even if we can't flush
        ngx.log(ngx.DEBUG, "Rescheduling metrics timer for worker " .. ngx.worker.id() .. " in " .. FLUSH_INTERVAL .. " seconds")
        local ok, err = ngx.timer.at(FLUSH_INTERVAL, flush_metrics_timer, env)
        if not ok then
            ngx.log(ngx.ERR, "Failed to reschedule metrics flush timer: " .. (err or "unknown error"))
        else
            ngx.log(ngx.DEBUG, "Metrics timer rescheduled successfully for worker " .. ngx.worker.id())
        end
        return
    end

    -- Try to acquire lock to prevent multiple workers from flushing simultaneously
    local lock_acquired = get_lock("arxignis_metrics_flush", FLUSH_INTERVAL)
    if lock_acquired then
        local batch_key = "current_metrics_batch"
        local batch_data = dict:get(batch_key)

        ngx.log(ngx.DEBUG, "Lock acquired, checking metrics batch data. Raw data: " .. (batch_data or "nil"))

        if batch_data and batch_data ~= "" then
            local success, batch = pcall(cjson.decode, batch_data)
            if success and #batch > 0 then
                ngx.log(ngx.DEBUG, "Found " .. #batch .. " metrics to flush, sending to API")
                make_batch_api_request(env, batch, "/metrics/batch")
                dict:set(batch_key, "")
                ngx.log(ngx.DEBUG, "Timer flushed " .. #batch .. " metrics from worker " .. ngx.worker.id())
            else
                ngx.log(ngx.DEBUG, "Metrics batch decode failed or empty batch. Success: " .. tostring(success) .. ", batch size: " .. (#batch or 0))
            end
        else
            ngx.log(ngx.DEBUG, "No metrics batch data found to flush")
        end
    else
        ngx.log(ngx.DEBUG, "Metrics lock not acquired, skipping flush but timer will continue")
    end

    -- Reschedule the timer for the next interval
    ngx.log(ngx.DEBUG, "Rescheduling metrics timer for worker " .. ngx.worker.id() .. " in " .. FLUSH_INTERVAL .. " seconds")
    local ok, err = ngx.timer.at(FLUSH_INTERVAL, flush_metrics_timer, env)
    if not ok then
        ngx.log(ngx.ERR, "Failed to reschedule metrics flush timer: " .. (err or "unknown error"))
    else
        ngx.log(ngx.DEBUG, "Metrics timer rescheduled successfully for worker " .. ngx.worker.id())
    end
end

-- Function to start the timers (call this in init_worker_by_lua)
function worker.start_flush_timers(env)
    ngx.log(ngx.DEBUG, "Starting flush timers for worker " .. ngx.worker.id())

    -- Start the logs timer
    local ok, err = ngx.timer.at(FLUSH_INTERVAL, flush_logs_timer, env)
    if not ok then
        ngx.log(ngx.ERR, "Failed to start logs flush timer: " .. (err or "unknown error"))
    else
       ngx.log(ngx.DEBUG, "Logs flush timer started successfully for worker " .. ngx.worker.id())
    end

    -- Start the metrics timer
    local ok2, err2 = ngx.timer.at(FLUSH_INTERVAL, flush_metrics_timer, env)
    if not ok2 then
        ngx.log(ngx.ERR, "Failed to start metrics flush timer: " .. (err2 or "unknown error"))
    else
        ngx.log(ngx.DEBUG, "Metrics flush timer started successfully for worker " .. ngx.worker.id())
    end

    -- Start the filter timer
    local ok3, err3 = ngx.timer.at(FLUSH_INTERVAL, flush_filter_timer, env)
    if not ok3 then
        ngx.log(ngx.ERR, "Failed to start filter flush timer: " .. (err3 or "unknown error"))
    else
        ngx.log(ngx.DEBUG, "Filter flush timer started successfully for worker " .. ngx.worker.id())
    end
end

-- Function to flush remaining logs (call this in worker shutdown)
function worker.flush_remaining_logs(env)
    local dict = ngx.shared[SHARED_DICT_NAME]
    if not dict then
        return
    end

    local batch_key = "current_batch"
    local batch_data = dict:get(batch_key)

    if batch_data and batch_data ~= "" then
        local success, batch = pcall(cjson.decode, batch_data)
        if success and #batch > 0 then
            make_batch_api_request(env, batch, "/log/batch")
            dict:set(batch_key, "")
            ngx.log(ngx.DEBUG, "Flushed remaining " .. #batch .. " logs from worker " .. ngx.worker.id())
        end
    end
end

-- Function to flush remaining metrics (call this in worker shutdown)
function worker.flush_remaining_filters(env)
    local dict = ngx.shared[SHARED_DICT_NAME]
    if not dict then
        return
    end

    process_filter_queue(env, dict)
end

function worker.flush_remaining_metrics(env)
    local dict = ngx.shared[SHARED_DICT_NAME]
    if not dict then
        return
    end

    local batch_key = "current_metrics_batch"
    local batch_data = dict:get(batch_key)

    if batch_data and batch_data ~= "" then
        local success, batch = pcall(cjson.decode, batch_data)
        if success and #batch > 0 then
            make_batch_api_request(env, batch, "/metrics/batch")
            dict:set(batch_key, "")
            ngx.log(ngx.DEBUG, "Flushed remaining " .. #batch .. " metrics from worker " .. ngx.worker.id())
        end
    end
end

return worker
