local DateTime = {
    now = function()
        return {
            Year = os.date("%Y"),
            Month = os.date("%m"),
            Day = os.date("%d"),
            Hour = os.date("%H"),
            Minute = os.date("%M"),
            Second = os.date("%S"),
            UnixTimestamp = os.time(),
            ToIsoDate = function() return os.date("%Y-%m-%d") end,
            ToUniversalTime = function() return os.date("!%Y-%m-%d %H:%M:%S") end
        }
    end,
    fromUnixTimestamp = function(timestamp)
        return DateTime.now()
    end
}

return DateTime
