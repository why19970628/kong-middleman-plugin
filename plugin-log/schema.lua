local typedefs = require "kong.db.schema.typedefs"
local date= os.date("%Y-%m-%d")

return {
  name = "file-log",
  fields = {
    { protocols = typedefs.protocols },
    { config = {
        type = "record",

        fields = {
          { path = { type = "string",
                     required = false,
                     match = [[^[^*&%%\`]+$]],
                     err = "not a valid filename",
                     default = "/tmp/"..date.."/"
          }, },
          { reopen = { type = "boolean", default = false }, },
    }, }, },
  }
}