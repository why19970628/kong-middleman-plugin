return {
    no_consumer = false, 
    fields = {
      redisPass = {type = "string", required = true, default = ""},
      redisHost = {type = "string", required = true, default = ""},
      redisPort = {type = "string", required = true, default = "6379"}
    }
}