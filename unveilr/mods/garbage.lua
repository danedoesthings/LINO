local IsGarbageString = function(str)
    if type(str) ~= "string" then return false end
    return #str > 30 and str:match("%d") and str:match("%W")
end

local SetGarbageData = function(data)
    -- Store garbage detection settings
end

return { IsGarbageString, SetGarbageData }
