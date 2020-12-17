local AuthHandler = {}
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local logwarn = kong.log.warn
local loginfo = kong.log.info
local logerr = kong.log.err
-- local utils = require("kong.plugins.sandan-auth.utils")

TokenIsEmpty = {err_code = 10400, err_msg = "redis token 为空"}
TokenNoExist = {err_code = 10401, err_msg = "token 不存在"}
TokenLengthErr = {err_code = 10401, err_msg = "token 长度错误"}
TokenNotMatch = {err_code = 10402, err_msg = "token 不匹配"}
TokenExpired = {err_code = 10403, err_msg = "token 已过期"}
CookieNoExist = {err_code = 10401, err_msg = "cookie 不存在"}
CookieNumErr = {err_code = 10401, err_msg = "cookie 参数数量错误"}

TokenLoginOtherDevice = {err_code = 10404, err_msg = "账号在其它设备登录"}
TokenLogout = {err_code = 10405, err_msg = "账号已退出"}
TokenForceLogout = {err_code = 10406, err_msg = "强制下线副设备"}
TokenValidator = {err_code = 10407, err_msg = "token 无效"}
RedisValidator = {err_code = 500, err_msg = "redis 连接失败"}
TokeArgsValidator = {err_code = 500, err_msg = "token 传参错误"}


function Split(szFullString, szSeparator)
    local nFindStartIndex = 1
    local nSplitIndex = 1
    local nSplitArray = {}
    while true do
        local nFindLastIndex = string.find(szFullString, szSeparator,
                                           nFindStartIndex)
        if not nFindLastIndex then
            nSplitArray[nSplitIndex] = string.sub(szFullString, nFindStartIndex,
                                                  string.len(szFullString))
            break
        end
        nSplitArray[nSplitIndex] = string.sub(szFullString, nFindStartIndex,
                                              nFindLastIndex - 1)
        nFindStartIndex = nFindLastIndex + string.len(szSeparator)
        nSplitIndex = nSplitIndex + 1
    end
    return nSplitArray
end


local ConvertListToTable = function(list)
    local info = {}
    for i = 1, #list, 2 do info[list[i]] = list[i + 1] end
    return info
end

function ResponseErr(res_data)
    response_data = {
        errmsg = res_data.err_msg,
        errcode = res_data.err_code,
        timestamp = ngx.time() * 1000,
    }
    kong.response.data = response_data
    kong.response.exit(401, response_data)
    return
end

---
-- @function: 打印table的内容，递归
-- @param: tbl 要打印的table
-- @param: level 递归的层数，默认不用传值进来
-- @param: filteDefault 是否过滤打印构造函数，默认为是
-- @return: return

function JwtHandler(access_token, jwtSecret)
    local jwt, err = jwt_decoder:new(access_token)
    if err ~= nil then
        ResponseErr(TokenValidator)
        return
    end
    local claims = jwt.claims
    if not (claims and type(claims.exp) == "number") then
        logwarn("invalid token claims")
        ResponseErr(TokenValidator)
        return
    end

    -- Verify "alg"
    local algorithm = claims.alg or "HS256"
    if jwt.header.alg ~= algorithm then
        ResponseErr(TokenValidator)
        return
    end

    -- Verify the JWT registered claims
    -- local ok, errors = jwt:verify_registered_claims({"alg", "typ"})

    -- Now verify the JWT signature
    -- 不是一个令牌
    -- local sign = access_token:match(".+%.(.*)")
    if not jwt:verify_signature(jwtSecret) then
        ResponseErr(TokenValidator)
        return
    end
    -- refresh_token 令牌失效 TODO
    -- local refresh_diff = claims.exp - ngx.time()
    -- if refresh_diff <= 0 then
    --     kong.response.exit(401, "refresh_token Expired expired= " .. claims.exp)
    --     return
    -- end
    -- 无法处理该令牌
    -- if not jwt:verify_signature(jwtSecret) then
    --     kong.response.exit(401, "Invalid signature TokenInvalid")
    --     return
    -- end

    -- 过期时间比对
    local diff = claims.exp - ngx.time()
    -- 令牌过期了
    if diff <= 0 then
        ResponseErr(TokenExpired)
        return
    end
end

function AuthHandler:access(plugin_conf)
    local redisHost = plugin_conf.redisHost
    local redisPort = plugin_conf.redisPort
    local redisPass = plugin_conf.redisPass
    local jwtSecret = plugin_conf.jwtSecret
    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeouts(1000, 1000, 1000) -- 1 sec
    local cookie = kong.request.get_header("cookie");
    -- 验证cookie长度, 未传cookie时local docker 默认17， 网关不穿默认24
    if cookie == nil or #cookie<=30 then
        ResponseErr(CookieNoExist)
        return
    end
    local list = Split(cookie, ";")
    local cookie_length = table.getn(list)
    if cookie_length < 8 then
        ResponseErr(CookieNumErr)
    end
    -- 传入cookie 字段顺序需要一致
    local uid = list[1]
    local access_token0 = list[2]
    local platform = list[6]
    if #access_token0 <=13 then
        ResponseErr(TokenLengthErr)
        return
    end
    local access_token = string.gsub(access_token0, "access_token=", "");
    -- 验证access_token是否为空
    if access_token == "" then
        ResponseErr(TokenNoExist)
        return
    end
    -- app:user:auth:{uid},{form}是否存在
    if (uid == '' or platform == '') then
        ResponseErr(TokeArgsValidator)
    end
    uid_ = string.gsub(uid, "uid=", "")
    from = string.gsub(platform, "platform=", "")
    if (uid_ == '' or from == '') then
        ResponseErr(TokeArgsValidator)
    end
    local authPrefix = "app:user:auth:"
    local authSubffix = uid_ .. "," .. from
    local ok, err = red:connect(redisHost, redisPort)
    if not ok then
        logwarn("failed to connect redis: ", err)
    else
        loginfo("connect redis success")
        if (redisPass ~= "") then
            local auth, err = red:auth(redisPass)
            if not auth then
                ResponseErr(RedisValidator)
            end
        end
        local res, _ = red:hgetall(authPrefix .. authSubffix)
        if not next(res) then
            ResponseErr(TokenIsEmpty)
        end
        res = ConvertListToTable(res)
        -- access_token是否一致
        if res.access_token ~= access_token then
            -- cookie中access_toke不一致
            local access_token_res_json =
                red:array_to_hash(red:hgetall(
                                      authPrefix .. authSubffix .. access_token))
            if not next(access_token_res_json) then
                ResponseErr(TokenNotMatch)
            end
            -- key..access_token 有值
            if next(access_token_res_json) then
                -- logwarn("redis def_permissions: ", access_token_res_json.ip,
                --         access_token_res_json.access_token,
                --         access_token_res_json.device_name,
                --         access_token_res_json.last_req_time,
                --         access_token_res_json.expire_time,
                --         access_token_res_json.type)
                local auth_type = access_token_res_json.type
                if auth_type == 0 then
                    -- 0 日常切换token，在TTL时间范围内还可以继续用该token请求接口
                    local sub_expire_time =
                        access_token_res_json.expire_time - ngx.time()
                    if sub_expire_time <= 300 then
                        ResponseErr(TokenExpired)
                    end
                elseif auth_type == 1 then
                    ResponseErr(TokenLoginOtherDevice)
                elseif auth_type == 2 then
                    ResponseErr(TokenLogout)
                elseif auth_type == 3 then
                    ResponseErr(TokenForceLogout)
                else
                    ResponseErr(TokenNotMatch)
                end
            end
        else
            -- access_token一致，效验jwt
            JwtHandler(access_token, jwtSecret)
        end
    end
    -- 使用连接池
    local ok, err = red:set_keepalive(100000, 10) -- (超时时间 ms, 连接池大小)
end

return AuthHandler