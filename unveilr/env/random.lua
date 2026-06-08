local Random = {
    new = function(seed)
        local rng = { seed = seed or os.time() }
        function rng:NextNumber(min, max)
            math.randomseed(self.seed)
            self.seed = self.seed + 1
            if min and max then
                return math.random(min, max)
            elseif min then
                return math.random(min)
            else
                return math.random()
            end
        end
        return rng
    end
}

return Random
