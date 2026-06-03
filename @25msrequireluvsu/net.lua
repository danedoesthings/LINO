local function request(opts)
 local url = opts.url or opts.Url
 local method = opts.method or opts.Method or "GET"
 local headers = opts.headers or opts.Headers or {}
 if method == "GET" then
  local result = process.exec("curl", {"-s", "-L", url})
  return {body = result.stdout, status = result.code}
 end
 return {body = "", status = 200}
end
return {request = request, jsonDecode = function(s) return {} end}
