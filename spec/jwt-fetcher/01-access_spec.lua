local helpers = require "spec.helpers"
local json = require "cjson"


local statusses = setmetatable({
  [200] = "200 OK",
  [404] = "404 NOT FOUND",
}, {
  __index = function(self, key)
    error("'"..tostring(key)"' is not a known status code")
  end
})

local port = 4000

-- rotate ports to prevent ports being in use
local function getport()
  local result = port
  port = port + 1
  if port >= 4100 then
    port = 4000
  end
  return result
end

-- Creates a 1-connection http server.
-- Accepts a single http request, sends the response and then terminates.
-- @param status (integer) status code to return in the response.
-- @param body (string/table) the body to return. If a table, will be json encoded.
-- @return port (where server is listening), thread. The thread can be used with
-- the result: `local success, request = thread:join()` to collect the request as received
local function http_server(status, body, ...)
  status = statusses[status]
  if not body then
    body = ""
  end
  if type(body) == "table" then
    body = json.encode(body)
  end

  local port = getport()
  local threads = require "llthreads2.ex"
  local thread = threads.new({
    function(port, status, body)
      local socket = require "socket"
      local server = assert(socket.tcp())
      assert(server:settimeout(10))
      assert(server:setoption('reuseaddr', true))
      assert(server:bind("*", port))
      assert(server:listen())
      local client = assert(server:accept())
      assert(client:settimeout(10))

      local request = {}
      local line, err
      while true do
        line, err = client:receive()
        if err or line == "" then
          -- exit loop on an error or if we're past the header section
          break
        else
          --table.insert(request, line)
          if request.method then
            -- there already is a method, so this is a regular header
            request.headers = request.headers or setmetatable({},{
                -- metamethod to do case-insensitive lookup
                __index = function(self, key)
                  assert(type(key) == "string", "expected header name to be a string")
                  key = key:upper()
                  for header, value in pairs(self) do
                    if header:upper() == key then
                      return value
                    end
                  end
                end,
              })
            local name, value = line:match("^([^:]-): (.-)$")
            request.headers[name] = value
          else
            -- no method yet, so this is the first line
            request.method, request.path, request.httpVersion = line:match("^(.-) (.-) (.-)$")
            if request.path:find("?",1,true) then
              -- there is a query in the path, extract it
              local query
              request.path, query = request.path:match("^(.-)%?(.+)$")
              query = require("pl.utils").split(query, "&")
              for i, entry in ipairs(query) do
                local name, value = entry:match("^(.-)=(.-)$")
                query[name] = (value == "") and true or value
                query[i] = nil
              end
              request.query = query
            end
          end
        end
      end

      if (not err) and request.headers["content-length"] then
        line, err = client:receive(tonumber(request.headers["content-length"]))
        request.data = line
      end

      if err then
        server:close()
        error(err)
      end

      client:send("HTTP/1.1 "..status.."\r\nConnection: close\r\n\r\n"..body)
      client:close()
      server:close()
      return request
    end
  }, port, status, body)

  return port, thread:start(...)
end


local plugin  -- forward declaration to hold the created plugin

-- start the test webserver, and update our plugin with the proper port
local function server(response, ...)
  local port, thread, err = http_server(response.status, response.body, ...)

  -- the server is at a dynamic port, so we must now patch the plugin
  -- config, to make it go to that port
  local admin = helpers.admin_client()
  local r = assert(admin:send {
    method = "PATCH",
    path = "/plugins/"..plugin.id,
    headers = {
      ["Content-Type"] = "application/json",
    },
    body = {
      config = {
        url = plugin.config.url:gsub(":%d+", ":"..port)
      },
    },
  })
  assert.response(r).has.status(200)
  admin:close()

  -- All done, server is up, plugin patched to proper port
  return thread, err
end



-- @param exp (in seconds) when to expire, eg. 10 => expires in 10
-- seconds, -1 => expired already
-- @param claims (table) a table to be used, `exp` will be inject if given
local function jwt(exp, claims)
  -- we don't need a full fledged JWT, just the claims need to be parsable
  if not exp then
    assert(claims, "claims must be provided if no 'exp' is given")
  else
    claims = claims or {}
    claims.exp = ngx.time() + exp
  end
  return (ngx.encode_base64("hello", true) .. "." ..
          ngx.encode_base64(json.encode(claims), true) .. "." ..
          ngx.encode_base64("world", true)):gsub("%-", "+"):gsub("_", "/")
end




for _, strategy in helpers.each_strategy() do
  describe("jwt-fetcher (access) [#" .. strategy .. "]", function()
    local client

    lazy_setup(function()
      local bp = helpers.get_db_utils(strategy)

      do -- create a route with key-auth, jwt-fetcher, consumer and credentails
        local route1 = bp.routes:insert({
          hosts = { "test1.com" },
        })

        plugin = bp.plugins:insert {
          name = "jwt-fetcher",
          route_id = route1.id,
          config = {
            url          = "http://localhost:123/getjwt",
            query_key    = "username",
            response_key = "access_token",
            timeout      = 60000,
            keepalive    = 60000,
            shm          = "kong_cache",
            negative_ttl = 10,
            skew         = 0,
          },
        }

        bp.plugins:insert {
          name = "key-auth",
          route_id = route1.id,
          config = {},
        }

        local consumer = bp.consumers:insert {
          username = "bobby",
          custom_id = "tintin"
        }

        bp.keyauth_credentials:insert {
          key         = "king-kong",
          consumer_id = consumer.id,
        }
      end

      do  -- route with only jwt-fetcher, no auth plugin
        local route2 = bp.routes:insert({
          hosts = { "test2.com" },
        })

        bp.plugins:insert {
          name = "jwt-fetcher",
          route_id = route2.id,
          config = {
            url          = "http://localhost:123/getjwt",
            query_key    = "username",
            response_key = "access_token",
            timeout      = 60000,
            keepalive    = 60000,
            shm          = "kong_cache",
            negative_ttl = 10,
            skew         = 0,
          },
        }
      end

      -- start kong
      assert(helpers.start_kong({
        -- set the strategy
        database   = strategy,
        -- use the custom test template to create a local mock server
        nginx_conf = "spec/fixtures/custom_nginx.template",
        -- set the config item to make sure our plugin gets loaded
        plugins = "bundled,jwt-fetcher",         -- since Kong CE 0.14
        custom_plugins = "jwt-fetcher",          -- pre Kong CE 0.14
      }))
    end)

    lazy_teardown(function()
      helpers.stop_kong(nil, true)
    end)

    before_each(function()
      client = helpers.proxy_client()
    end)

    after_each(function()
      if client then client:close() end
    end)



    describe("request", function()
      it("succeeds with a proper credential", function()
        local token = jwt(10)
        local thread = assert(server {
          -- define the response we want from the JWT test server
          status = 200,
          body = {
            access_token = token,
          }
        })
        -- Now hit Kong with a request
        local r = assert(client:send {
          method = "GET",
          path = "/",
          headers = {
            host = "test1.com",
            apikey = "king-kong",
          }
        })
        -- validate that the request succeeded, response status 200
        assert.response(r).has.status(200)

        -- validate the request for fetching the JWT
        local ok, jwt_request = thread:join()
        assert.is_True(ok)
        assert.are.equal("/getjwt", jwt_request.path)
        assert.are.equal("tintin", jwt_request.query.username)

        -- validate the upstream header to be the token we got
        local header_value = assert.request(r).has.header("Authorization")
        assert.equal("Bearer " .. token, header_value)
      end)


      it("token gets cached for 'exp' time", function()
        local token = jwt(1)    -- 1 second cache time
        local thread = assert(server {
          -- define the response we want from the JWT test server
          status = 200,
          body = {
            access_token = token,
          }
        })
        -- Now hit Kong with a request
        local r = assert(client:send {
          method = "GET",
          path = "/",
          headers = {
            host = "test1.com",
            apikey = "king-kong",
          }
        })
        assert(thread:join())  -- close up server

        -- validate that the request succeeded, response status 200
        assert.response(r).has.status(200)

        -- now, without setting up a JWT server, we try again, as it should
        -- be served from the Kong cache
        r = assert(client:send {
          method = "GET",
          path = "/",
          headers = {
            host = "test1.com",
            apikey = "king-kong",
          }
        })
        assert.response(r).has.status(200)
        -- validate the upstream header to be the cached token we created
        local header_value = assert.request(r).has.header("Authorization")
        assert.equal("Bearer " .. token, header_value)

        -- wait for expiry
        ngx.sleep(2)

        -- Now hit Kong with a request, without having set up another server
        -- so the Request should fail with a 500, connection refused
        r = assert(client:send {
          method = "GET",
          path = "/",
          headers = {
            host = "test1.com",
            apikey = "king-kong",
          }
        })

        assert.response(r).has.status(500)
      end)


      it("fails with 403 on an expired JWT", function()
        local token = jwt(-10)
        local thread = assert(server {
          -- define the response we want from the JWT test server
          status = 200,
          body = {
            access_token = token,
          }
        })
        -- Now hit Kong with a request
        local r = assert(client:send {
          method = "GET",
          path = "/",
          headers = {
            host = "test1.com",
            apikey = "king-kong",
          }
        })
        assert(thread:join())  -- close up server
        assert.response(r).has.status(403)
      end)


      it("fails with 500 on an unavailable JWT server", function()
        -- Just hit Kong with a request, JWT fetcher willl get "connection refused"
        local r = assert(client:send {
          method = "GET",
          path = "/",
          headers = {
            host = "test1.com",
            apikey = "king-kong",
          }
        })

        assert.response(r).has.status(500)
      end)


      it("fails with 500 on an invalid JWT", function()
        local token = "ThisIsNotAValidJWT"
        local thread = assert(server {
          -- define the response we want from the JWT test server
          status = 200,
          body = {
            access_token = token,
          }
        })
        -- Now hit Kong with a request
        local r = assert(client:send {
          method = "GET",
          path = "/",
          headers = {
            host = "test1.com",
            apikey = "king-kong",
          }
        })
        assert(thread:join())  -- close up server
        assert.response(r).has.status(500)
      end)


      it("unauthenticated gets a 403 (with key-auth)", function()
        local r = assert(client:send {
          method = "GET",
          path = "/",
          headers = {
            host = "test1.com",
            apikey = "king-but-not-kong",
          }
        })

        assert.response(r).has.status(403)
      end)


      it("unauthenticated gets a 403 (no auth, just jwt-fetcher)", function()
        local r = assert(client:send {
          method = "GET",
          path = "/",
          headers = {
            host = "test2.com",
          }
        })

        assert.response(r).has.status(403)
      end)

    end)

  end)

end
