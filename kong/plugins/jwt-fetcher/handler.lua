--- Some design choices:
--
-- - only cache in SHM, since it is a single string value, adding lua-land
--   lru caches seems just a waste of memory
-- - shm cache is indexed by the custom_id, so we assume a single remote server
--   if multiple plugin instances use different remote servers it could
--   cause collissions in then shm (effectively using the wrong JWT)
-- - 404 expected if custom_id isn't found, makes it harder to spot errors
--   when configured with a bad path...
-- - 200 expected if custom_id is found and a jwt is returned
-- - JWT validates exp only! downstream is doing validation!

-- endpoint returns 200 for ok, everything else should result in a 500 from Kong with the error messages logged in Kong logs.
-- validate cache key to reuse plugin


local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")  -- Grab pluginname from module name



-- Constants
local NOT_FOUND_TOKEN = -1  -- value MUST be illegal as a JWT string, but thruthy
local SHM_PREFIX = "[" .. plugin_name .. "]:"
local EMPTY = require("pl.tablex").readonly({})
local SCHEME_ID, HOST_ID, PORT_ID, PATH_ID, QUERY_ID = 1,2,3,4,5



-- Modules
local json_decode = require("cjson.safe").decode
local resty_lock = require "resty.lock"
local responses = require "kong.tools.responses"
local http = require "resty.http"



-- Locals
local ngx_req_set_header = ngx.req.set_header
local ngx_decode_base64 = ngx.decode_base64
local string_rep = string.rep
local url_cache = setmetatable({},{__mode="k"}) -- weak cache for parsed urls
local md5_cache = setmetatable({},{__mode="k"}) -- weak cache for url md5 hashes
local ngx_now = ngx.now
local ngx_md5 = ngx.md5
local ngx_log = ngx.log
local ngx_ERR = ngx.ERR
local ngx_WARN = ngx.WARN

-- load the base plugin object and create a subclass
local plugin = require("kong.plugins.base_plugin"):extend()

-- set the plugin priority, which determines plugin execution order
-- See: https://docs.konghq.com/1.0.x/plugin-development/custom-logic/#plugins-execution-order
plugin.PRIORITY = 940  -- run after auth plugins and acl, but before rate-limiting
--plugin.PRIORITY = 850  -- run after rate-limiting

-- constructor
function plugin:new()
  plugin.super.new(self, plugin_name)
end


local function get_shm_key(conf, id)
  -- we're using an MD5 of the url in the cache key, such that multiple
  -- backend servers are in their own namespace in the cache without collissions
  local url = conf.url
  local md5 = md5_cache[url]
  if not md5 then
    md5 = ngx_md5(url)
    md5_cache[url] = md5
  end
  return SHM_PREFIX .. md5 .. "-" ..id
end


-- Fetches JWT from remote server.
-- @param conf plugin configuration
-- @param id the custom_id for which to find the JWT
-- @return jwt, or nil if not found, or nil+err in case of error
local function fetch_jwt(conf, id)
  local client = http.new()
  client:set_timeout(conf.timeout)

  -- get url from cache, so we do not parse the url on each request, and we
  -- prepare the query element
  local url_elements = url_cache[conf]
  if not url_elements then
    url_elements = client:parse_uri(conf.url, false)
    local query = url_elements[QUERY_ID]
    if query == "" then query = nil end
    query = query and "?" .. query .. "&" .. conf.query_key .. "="
                  or "?" .. conf.query_key .. "="
    url_elements[QUERY_ID] = query
    -- store it in the cache
    url_cache[conf] = url_elements
  end

  assert(client:connect(url_elements[HOST_ID], url_elements[PORT_ID]))

  if url_elements[SCHEME_ID] == "https" then
    assert(client:ssl_handshake())
  end

  local res, err = client:request {
    method = "GET",
    path = url_elements[PATH_ID] .. url_elements[QUERY_ID] .. id,
  }
  if not res then
    client:close()
    error("failed sending request: " .. tostring(err))
  end

  local body = res:read_body()
  local status = res.status

  local ok
  ok, err = client:set_keepalive(conf.keepalive)
  if not ok then
    client:close()
    ngx_log(ngx_WARN, "failed setting keepalive: ", err)
  end

  if status < 200 or status > 299 then
    -- an unexpected response
    return nil, ("bad status code received '%s', expected 2xx. Body: %s"):format(tostring(status), body or "")
  end

  -- we received a 2xx
  local jwt
  local json = json_decode(body)
  if (conf.response_key or "") == "" then
    -- no object just a json string value
    if type(json) ~= "string" then
      return nil, "expected json string value, got: " .. tostring(json)
    end
    jwt = json
  else
    -- json object
    if type(json) ~= "table" then
      return nil, "expected json object, got: " .. tostring(json)
    end
    jwt = json[conf.response_key]
    if type(jwt) ~= "string" then
      return nil, ("expected json object to have a string value named " ..
                   "'%s', got: %s"):format(conf.response_key, tostring(jwt))
    end
  end

  return jwt
end


-- base 64 decode
-- @param input String to base64 decode
-- @return Base64 decoded string
local function base64_decode(input)
  local remainder = #input % 4

  if remainder > 0 then
    local padlen = 4 - remainder
    input = input .. string_rep("=", padlen)
  end

  input = input:gsub("-", "+"):gsub("_", "/")
  return ngx_decode_base64(input)
end


local parse_err = function(err)
  return "invalid jwt" .. (err and (": " .. err) or "")
end


-- Returns the ttl for this JWT token.
-- @param jwt the JWT to parse
-- @return ttl in seconds, or nil+err
local function parse_jwt_ttl(conf, jwt)

  local err = nil
  local s = jwt:find(".",1, true)  -- first dot
  if not s then error(parse_err(err)) end

  local e = jwt:find(".", s + 1, true)  -- second dot
  if not s then error(parse_err(err)) end

  local data
  data = jwt:sub(s + 1, e - 1)
  data, err = base64_decode(data)
  if not data then error(parse_err(err)) end

  local claims
  claims, err = json_decode(data)
  if not claims then error(parse_err(err)) end

  local exp
  exp = claims.exp
  if not exp then error(parse_err("missing 'exp' claim")) end

  local ttl =  (tonumber(exp) or 0) - ngx_now() + conf.skew
  if ttl <= 0 then return nil, parse_err("expired") end

  return ttl
end


-- Runs a function inside a lock.
-- Ensures only one runs at a time for the given key.
-- @param conf plugin configuration
-- @param key the key to identify the lock
-- @param f function to run, MUST return max 2 values!
local function run_in_lock(conf, key, f)
  local lock, ok, err
  -- create lock
  lock, err = resty_lock:new(conf.shm)
  if not lock then
    return nil, "failed to create lock: " .. tostring(err)
  end

  -- acquire lock
  ok, err = lock:lock("[lock]"..key)
  if not ok then
    return nil, "failed to acquire lock: " .. tostring(err)
  end

  -- execute function
  local r_ok, r_result, r_err = pcall(f)

  -- release lock
  ok, err = lock:unlock()
  if not ok then
    return nil, "failed to release lock: " .. tostring(err)
  end

  if not r_ok then
    -- was a hard error, so 'result' holds the error, re-throw outside lock
    error(r_result)
  end

  return r_result, r_err  -- either success or a soft error
end


-- Gets the JWT from cache, or goes fetch it remotely otherwise.
-- @param conf plugin configuration
-- @param id the custom_id for which to find the JWT
-- @return jwt, or nil if not found, or nil+err in case of error
local function get_jwt(conf, id)
  local shm = ngx.shared[conf.shm]
  local key = get_shm_key(conf, id)

  if not shm then
    error(("shm by name '%s' not found"):format(tostring(conf.shm)))
  end

  local jwt, err = shm:get(key)
  if err then
    error("failed to get shm value: " .. tostring(err))

  elseif jwt then
    return jwt ~= NOT_FOUND_TOKEN and jwt or nil  -- return cached result
  end

  -- not cached, so go and look it up
  jwt, err = run_in_lock(conf, key, function()
      -- we acquired a lock by now, so first check whether we by
      -- now have a cached value
      local jwt, err = shm:get(key)
      if err then
        error("failed to get shm value: " .. tostring(err))

      elseif jwt then
        return jwt  -- return cached result, do NOT resolve the NOT_FOUND_TOKEN
      end

      -- still nothing, so actually go and fetch it
      return fetch_jwt(conf, id)
    end)

  if err then
    return nil, err
  end

  if jwt == NOT_FOUND_TOKEN then
    -- we got this inside the lock, when we retried, so some other worker/request
    -- put it in the cache, nothing more for us to do since it is already in the
    -- cache and we do not want to override the ttl as set by the first worker
    return nil
  end

  local ttl
  if not jwt then
    -- no JWT, so do negative caching
    jwt = NOT_FOUND_TOKEN
    ttl = conf.negative_ttl/1000  -- convert to seconds

  else
    -- got a JWT, go check the ttl
    ttl, err = parse_jwt_ttl(conf, jwt)
    if not ttl then
      return nil, err   -- we failed to parse the JWT
    end
  end

  -- Store JWT in cache for future use
  local ok
  ok, err = shm:set(key, jwt, ttl)
  if not ok then
    -- log error, since this is non-fatal
    ngx_log(ngx_ERR, "Failed to store JWT in cache: ", err)
  end

  return jwt ~= NOT_FOUND_TOKEN and jwt or nil
end



function plugin:access(conf)
  plugin.super.access(self)

  local id = (ngx.ctx.authenticated_consumer or EMPTY).custom_id
  if id then
    local jwt, err = get_jwt(conf, id)
    if err then
      ngx_log(ngx_ERR, "jwt-fetcher error: ", err)
    else
      -- we have a valid JWT
      ngx_req_set_header("Authorization", "Bearer " .. jwt)
      return -- all is well
    end
  end

  responses.send_HTTP_FORBIDDEN("You cannot consume this service")
end



-- return our plugin object
return plugin
