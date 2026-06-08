local InstanceLib = {
    Object = {
        properties = {},
        methods = {},
        callbacks = {}
    }
}

local InstanceFuncs = {
    IsA = function(className, target) return className == target end
}

return { InstanceLib, InstanceFuncs }
