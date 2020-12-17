-- Copyright (C) Kong Inc.
local ffi = require "ffi"
local cjson = require "cjson"
local system_constants = require "lua_system_constants"


local kong = kong


local O_CREAT = system_constants.O_CREAT()
local O_WRONLY = system_constants.O_WRONLY()
local O_APPEND = system_constants.O_APPEND()
local S_IRUSR = system_constants.S_IRUSR()
local S_IWUSR = system_constants.S_IWUSR()
local S_IRGRP = system_constants.S_IRGRP()
local S_IROTH = system_constants.S_IROTH()


local oflags = bit.bor(O_WRONLY, O_CREAT, O_APPEND)
local mode = bit.bor(S_IRUSR, S_IWUSR, S_IRGRP, S_IROTH)


local C = ffi.C


ffi.cdef [[
int write(int fd, const void * ptr, int numbytes);
]]



function file_exists(path)
  local file = io.open(path, "rb")
  if file then file:close() 
  end
  if file == nil then
      os.execute('mkdir '..path)
  end
end

-- fd tracking utility functions
local file_descriptors = {}

-- Log to a file. Function used as callback from an nginx timer.
-- @param `premature` see OpenResty `ngx.timer.at()`
-- @param `conf`     Configuration table, holds http endpoint details
-- @param `message`  Message to be logged
local function log(conf, message)
  local msg = cjson.encode(message) .. "\n"
  local file_preffix = os.date("%H")
  local date= os.date("%Y-%m-%d")
  local log_path = "/tmp/log"
  file_exists(log_path)
  local file_folder = log_path.."/"..date
  file_exists(file_folder)
  local path = file_folder.."/"..file_preffix..".log"
  local fd = file_descriptors[path]

  if fd and conf.reopen then
    -- close fd, we do this here, to make sure a previously cached fd also
    -- gets closed upon dynamic changes of the configuration
    C.close(fd)
    file_descriptors[path] = nil
    fd = nil
  end

  if not fd then
    fd = C.open(path, oflags, mode)
    if fd < 0 then
      local errno = ffi.errno()
      kong.log.err("failed to open the file: ", ffi.string(C.strerror(errno)))

    else
      file_descriptors[path] = fd
    end
  end

  C.write(fd, msg, #msg)
end


local FileLogHandler = {
  PRIORITY = 9,
  VERSION = "2.0.2",
}

function FileLogHandler:log(conf)
  local message = kong.log.serialize()
  message.response_data = kong.response.data
  log(conf, message)
end
return FileLogHandler