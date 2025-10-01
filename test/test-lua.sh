#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

resty   -I ./rootfs/etc/nginx/lua   -I ./lua-resty-arxignis/lib   --shdict "configuration_data 5M"   --shdict "certificate_data 16M"   --shdict "certificate_servers 1M"   --shdict "ocsp_response_cache 1M"   --shdict "balancer_ewma 1M"   --shdict "quota_tracker 1M"   --shdict "high_throughput_tracker 1M"   --shdict "balancer_ewma_last_touched_at 1M"   --shdict "balancer_ewma_locks 512k"   --shdict "arxignis_queue 5M"   ./rootfs/etc/nginx/lua/test/run.lua   ./lua-resty-arxignis/spec/   -v --pattern=_test
