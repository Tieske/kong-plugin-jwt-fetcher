return {
  no_consumer = true,
  fields = {
    url = {
      -- URL of remote server where to fetch the JWT
      -- Can use HTTP/HTTPS
      type = "string",
      required = true,
    },
    query_key = {
      -- the query key/name in which to store the custom id send to the
      -- remote server
      type = "string",
      default = "username",
      required = true,
    },
    response_key = {
      -- the key, in the JSON body response that contains the JWT. Assumes the
      -- body to be a JSON object. If not provided, it will assume the JWT
      -- in in a top-level JSON string value
      type = "string",
      default = "access_token",
    },
    timeout = {
      -- timeout when making the http request to fetch the JWT (in seconds)
      type = "integer",
      default = 60,
      required = true,
    },
    keepalive = {
      -- connection keepalive in milliseconds
      type = "number",
      default = 60000,
      required = true,
    },
    shm = {
      -- the shm to use as node level cache
      type = "string",
      default = "jwtstore",
      required = true,
    },
    negative_ttl = {
      -- if a JWT is not on the remote server, how long to cache that fact
      type = "integer",
      default = 10,
      required = true,
    },
    skew = {
      -- Max clock skew to compensate ('exp' claim is extended with
      -- this) in seconds
      type = "integer",
      default = 0,
      required = true,
    },
  },
  self_check = function(schema, plugin_t, dao, is_updating)
    -- TODO: perform any custom verification?
    return true
  end
}
