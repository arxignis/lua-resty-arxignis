package = "lua-resty-arxignis"
version = "1.2-2"
source = {
   url = "git+https://github.com/arxignis/lua-resty-arxignis.git",
   tag = "v1.2-2"
}
description = {
   summary = "Arxignis integration for OpenResty/nginx",
   detailed = [[
      A comprehensive integration package for OpenResty/nginx that provides
      Arxignis security features including captcha handling, logging,
      metrics collection, and remediation capabilities.
   ]],
   homepage = "https://github.com/arxignis/lua-resty-arxignis",
   license = "Apache2"
}
dependencies = {
   "lua >= 5.1",
   "lua-resty-core >= 0.1.0",
   "lua-resty-http >= 0.15.0",
   "lua-resty-mlcache >= 2.6.0",
   "lua-resty-jwt >= 0.2.3",
   "lua-resty-cookie >= 0.4.1",
   "lua-resty-http >= 0.17.2"
}
build = {
   type = "builtin",
   modules = {
      ["resty.arxignis"] = "lib/resty/arxignis.lua",
      ["resty.arxignis.logger"] = "lib/resty/arxignis/logger.lua",
      ["resty.arxignis.captcha"] = "lib/resty/arxignis/captcha.lua",
      ["resty.arxignis.metrics"] = "lib/resty/arxignis/metrics.lua",
      ["resty.arxignis.remediation"] = "lib/resty/arxignis/remediation.lua",
      ["resty.arxignis.worker"] = "lib/resty/arxignis/worker.lua",
      ["resty.arxignis.utils"] = "lib/resty/arxignis/utils.lua",
      ["resty.arxignis.template"] = "lib/resty/arxignis/template.lua",
      ["resty.arxignis.log"] = "lib/resty/arxignis/log.lua"
   }
}
