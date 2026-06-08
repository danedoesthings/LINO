--[=[if type(game) ~= "userdata" then print("errored") end
if type(workspace) ~= "userdata" then print("errored") end
if type(game.Players) ~= "userdata" then print("errored") end
if type(game.Players.LocalPlayer) ~= "userdata" then print("errored") end
if type(game.Lighting) ~= "userdata" then print("errored") end
if type(game.ReplicatedStorage) ~= "userdata" then print("errored") end
if type(game.ReplicatedFirst) ~= "userdata" then print("errored") end
if type(game.StarterGui) ~= "userdata" then print("errored") end
if type(game.StarterPack) ~= "userdata" then print("errored") end
if type(game.StarterPlayer) ~= "userdata" then print("errored") end
if type(game.Teams) ~= "userdata" then print("errored") end
if type(game.SoundService) ~= "userdata" then print("errored") end
if type(game.Chat) ~= "userdata" then print("errored") end
if type(game.LocalizationService) ~= "userdata" then print("errored") end
if type(game.TestService) ~= "userdata" then print("errored") end
if type(game:GetService("Players")) ~= "userdata" then print("errored") end
if type(game:GetService("Workspace")) ~= "userdata" then print("errored") end
if type(game:GetService("RunService")) ~= "userdata" then print("errored") end
if type(game:GetService("UserInputService")) ~= "userdata" then print("errored") end
if type(game:GetService("TweenService")) ~= "userdata" then print("errored") end
if type(game:GetService("HttpService")) ~= "userdata" then print("errored") end
if type(game:GetService("MarketplaceService")) ~= "userdata" then print("errored") end
if type(Instance.new("Part")) ~= "userdata" then print("errored") end
if typeof(game) ~= "Instance" then print("errored") end
if typeof(workspace) ~= "Instance" then print("errored") end
if typeof(game.Players.LocalPlayer) ~= "Instance" then print("errored") end
if game.ClassName ~= "DataModel" then print("errored") end
if workspace.ClassName ~= "Workspace" then print("errored") end
if game.Players.ClassName ~= "Players" then print("errored") end
if type(print) ~= "function" then print("errored") end
if type(warn) ~= "function" then print("errored") end
if type(error) ~= "function" then print("errored") end
if type(assert) ~= "function" then print("errored") end
if type(pcall) ~= "function" then print("errored") end
if type(xpcall) ~= "function" then print("errored") end
if type(game.GetService) ~= "function" then print("errored") end
if type(game.FindFirstChild) ~= "function" then print("errored") end
if type(Instance.new) ~= "function" then print("errored") end
if type(getmetatable) ~= "function" then print("errored") end
if type(setmetatable) ~= "function" then print("errored") end
if type(rawget) ~= "function" then print("errored") end
if type(rawset) ~= "function" then print("errored") end
if type(next) ~= "function" then print("errored") end
if type(pairs) ~= "function" then print("errored") end
if type(ipairs) ~= "function" then print("errored") end
if type(tostring) ~= "function" then print("errored") end
if type(tonumber) ~= "function" then print("errored") end
if type(select) ~= "function" then print("errored") end
if type(tick) ~= "function" then print("errored") end
if type(wait) ~= "function" then print("errored") end
if type(spawn) ~= "function" then print("errored") end
if type(delay) ~= "function" then print("errored") end
if type(_G) ~= "table" then print("errored") end
if type(shared) ~= "table" then print("errored") end
if type(math) ~= "table" then print("errored") end
if type(string) ~= "table" then print("errored") end
if type(table) ~= "table" then print("errored") end
if type(coroutine) ~= "table" then print("errored") end
if type(debug) ~= "table" then print("errored") end
if type(os) ~= "table" then print("errored") end
if type(utf8) ~= "table" then print("errored") end
if type(bit32) ~= "table" then print("errored") end
if type(math.pi) ~= "number" then print("errored") end
if type(math.huge) ~= "number" then print("errored") end
if type(true) ~= "boolean" then print("errored") end
if type(false) ~= "boolean" then print("errored") end
if type(nil) ~= "nil" then print("errored") end
if workspace.Parent ~= game then print("errored") end
if game.Players.LocalPlayer.Parent ~= game.Players then print("errored") end
if getmetatable(game) == nil then print("errored") end
if getmetatable(workspace) == nil then print("errored") end
if game:GetService("Players") == nil then print("errored") end
if game:GetService("Workspace") == nil then print("errored") end
if game:GetService("RunService") == nil then print("errored") end
if game.PlaceId == 0 then print("errored") end
if game.JobId == "" and not game:GetService("RunService"):IsStudio() then print("errored") end
if type(game:GetService("ContentProvider")) ~= "userdata" then print("errored") end
if type(game:GetService("Debris")) ~= "userdata" then print("errored") end
if type(game:GetService("InsertService")) ~= "userdata" then print("errored") end
if type(game:GetService("LogService")) ~= "userdata" then print("errored") end
if type(game:GetService("PhysicsService")) ~= "userdata" then print("errored") end
if type(game:GetService("Stats")) ~= "userdata" then print("errored") end
if type(game:GetService("TeleportService")) ~= "userdata" then print("errored") end
if type(game:GetService("TextService")) ~= "userdata" then print("errored") end
if type(game:GetService("VirtualUser")) ~= "userdata" then print("errored") end
if type(game:GetService("GuiService")) ~= "userdata" then print("errored") end
if type(game:GetService("VirtualInputManager")) ~= "userdata" then print("errored") end
if type(game:GetService("ContextActionService")) ~= "userdata" then print("errored") end
if type(game:GetService("PathfindingService")) ~= "userdata" then print("errored") end
if type(game.Players.LocalPlayer.Character) ~= "userdata" then print("errored") end
if type(game.Players.LocalPlayer:FindFirstChild("PlayerGui")) ~= "userdata" then print("errored") end
if typeof(game.Players.LocalPlayer.Character) ~= "Instance" then print("errored") end
if game.Players.LocalPlayer.Character == nil then print("errored") end
if game.Players.LocalPlayer.Character.Parent ~= workspace then print("errored") end
if type(game.Players.LocalPlayer:GetMouse()) ~= "userdata" then print("errored") end
if typeof(game.Players.LocalPlayer:GetMouse()) ~= "Instance" then print("errored") end
if game.GameId == nil then print("errored") end
if game.CreatorId == nil then print("errored") end
if type(task) ~= "table" then print("errored") end
if type(task.wait) ~= "function" then print("errored") end
if type(task.spawn) ~= "function" then print("errored") end
if type(task.defer) ~= "function" then print("errored") end
if type(type) ~= "function" then print("errored") end
if type(typeof) ~= "function" then print("errored") end
if type(unpack) ~= "function" then print("errored") end
if type(loadstring) ~= "function" then print("errored") end
if string.len ~= string.len then print("errored") end
if math.floor ~= math.floor then print("errored") end
if table.insert ~= table.insert then print("errored") end
if workspace.Name ~= "Workspace" then print("errored") end
if game.Players.LocalPlayer.Name == "" then print("errored") end
if game.Players.LocalPlayer.UserId == 0 then print("errored") end
if game.Players.LocalPlayer.UserId < 0 then print("errored") end
if game:GetService("CoreGui") == nil then print("errored") end
if type(game:GetService("CoreGui")) ~= "userdata" then print("errored") end
if type(game:GetService("ReplicatedStorage")) ~= "userdata" then print("errored") end
if type(game:GetService("ReplicatedFirst")) ~= "userdata" then print("errored") end
if type(game:GetService("ServerStorage")) ~= "userdata" then print("errored") end
if type(game:GetService("ServerScriptService")) ~= "userdata" then print("errored") end
if type(game:GetService("StarterGui")) ~= "userdata" then print("errored") end
if type(game:GetService("StarterPack")) ~= "userdata" then print("errored") end
if type(game:GetService("StarterPlayer")) ~= "userdata" then print("errored") end
if type(game:GetService("Teams")) ~= "userdata" then print("errored") end
if type(game:GetService("SoundService")) ~= "userdata" then print("errored") end
if type(game:GetService("Chat")) ~= "userdata" then print("errored") end
if type(game:GetService("LocalizationService")) ~= "userdata" then print("errored") end
if type(game:GetService("TestService")) ~= "userdata" then print("errored") end
if type(game:GetService("Lighting")) ~= "userdata" then print("errored") end
if typeof(game.Lighting) ~= "Instance" then print("errored") end
if typeof(game.ReplicatedStorage) ~= "Instance" then print("errored") end
if typeof(game.ReplicatedFirst) ~= "Instance" then print("errored") end
if game.Lighting.ClassName ~= "Lighting" then print("errored") end
if game.ReplicatedStorage.ClassName ~= "ReplicatedStorage" then print("errored") end
if game.ReplicatedFirst.ClassName ~= "ReplicatedFirst" then print("errored") end
if game.StarterGui.ClassName ~= "StarterGui" then print("errored") end
if game.Players.LocalPlayer.ClassName ~= "Player" then print("errored") end
if type(game.Players.LocalPlayer.Character:FindFirstChild("Humanoid")) ~= "userdata" then print("errored") end
if typeof(game.Players.LocalPlayer.Character:FindFirstChild("Humanoid")) ~= "Instance" then print("errored") end
if game.Players.LocalPlayer.Character:FindFirstChild("Humanoid").ClassName ~= "Humanoid" then print("errored") end
if type(game.Players.LocalPlayer.Character:FindFirstChild("HumanoidRootPart")) ~= "userdata" then print("errored") end
if typeof(game.Players.LocalPlayer.Character:FindFirstChild("HumanoidRootPart")) ~= "Instance" then print("errored") end
if game.Players.LocalPlayer.Character:FindFirstChild("HumanoidRootPart").ClassName ~= "Part" then print("errored") end
if type(Vector3) ~= "table" then print("errored") end
if type(Vector3.new) ~= "function" then print("errored") end
if type(CFrame) ~= "table" then print("errored") end
if type(CFrame.new) ~= "function" then print("errored") end
if type(Color3) ~= "table" then print("errored") end
if type(Color3.new) ~= "function" then print("errored") end
if type(UDim2) ~= "table" then print("errored") end
if type(UDim2.new) ~= "function" then print("errored") end
if type(UDim) ~= "table" then print("errored") end
if type(UDim.new) ~= "function" then print("errored") end
if type(Vector2) ~= "table" then print("errored") end
if type(Vector2.new) ~= "function" then print("errored") end
if type(NumberRange) ~= "table" then print("errored") end
if type(NumberRange.new) ~= "function" then print("errored") end
if type(NumberSequence) ~= "table" then print("errored") end
if type(NumberSequence.new) ~= "function" then print("errored") end
if type(ColorSequence) ~= "table" then print("errored") end
if type(ColorSequence.new) ~= "function" then print("errored") end
if type(Ray) ~= "table" then print("errored") end
if type(Ray.new) ~= "function" then print("errored") end
if type(Axes) ~= "table" then print("errored") end
if type(Axes.new) ~= "function" then print("errored") end
if type(Faces) ~= "table" then print("errored") end
if type(Faces.new) ~= "function" then print("errored") end
if type(BrickColor) ~= "table" then print("errored") end
if type(BrickColor.new) ~= "function" then print("errored") end
if type(Region3) ~= "table" then print("errored") end
if type(Region3.new) ~= "function" then print("errored") end
if type(PhysicalProperties) ~= "table" then print("errored") end
if type(PhysicalProperties.new) ~= "function" then print("errored") end
if type(Random) ~= "table" then print("errored") end
if type(Random.new) ~= "function" then print("errored") end
if type(TweenInfo) ~= "table" then print("errored") end
if type(TweenInfo.new) ~= "function" then print("errored") end
if game.PlaceVersion == nil then print("errored") end
if game.Workspace ~= workspace then print("errored") end
if game.workspace ~= workspace then print("errored") end
if typeof(game.Players.LocalPlayer:WaitForChild("PlayerGui")) ~= "Instance" then print("errored") end
if game.Players.LocalPlayer.PlayerGui.ClassName ~= "PlayerGui" then print("errored") end
if type(game.Players.LocalPlayer:GetChildren()) ~= "table" then print("errored") end
if type(workspace:GetChildren()) ~= "table" then print("errored") end
if type(game:GetChildren()) ~= "table" then print("errored") end
if type(game.Players:GetPlayers()) ~= "table" then print("errored") end
if type(game.Players.LocalPlayer.Character:GetChildren()) ~= "table" then print("errored") end
if type(Instance) ~= "table" then print("errored") end
if type(game.Destroy) ~= "function" then print("errored") end
if type(workspace.Destroy) ~= "function" then print("errored") end
if type(game.Clone) ~= "function" then print("errored") end
if type(game.IsA) ~= "function" then print("errored") end
if type(game.FindFirstChild) ~= "function" then print("errored") end
if type(game.WaitForChild) ~= "function" then print("errored") end
if type(game.GetChildren) ~= "function" then print("errored") end
if type(game.GetDescendants) ~= "function" then print("errored") end
if type(workspace:IsA("Workspace")) ~= "boolean" then print("errored") end
if type(game:IsA("DataModel")) ~= "boolean" then print("errored") end
if game:IsA("Workspace") == true then print("errored") end
if workspace:IsA("DataModel") == true then print("errored") end
if game:IsA("DataModel") ~= true then print("errored") end
if workspace:IsA("Workspace") ~= true then print("errored") end
if type(game.GetFullName) ~= "function" then print("errored") end
if type(workspace.GetFullName) ~= "function" then print("errored") end
if workspace:GetFullName() ~= "Workspace" then print("errored") end
if type(workspace.FindFirstChildOfClass) ~= "function" then print("errored") end
if type(workspace.FindFirstChildWhichIsA) ~= "function" then print("errored") end
if type(workspace.GetPropertyChangedSignal) ~= "function" then print("errored") end
if type(game.GetPropertyChangedSignal) ~= "function" then print("errored") end
if type(game.IsLoaded) ~= "function" then print("errored") end
if typeof(Vector3.new(0,0,0)) ~= "Vector3" then print("errored") end
if typeof(CFrame.new(0,0,0)) ~= "CFrame" then print("errored") end
if typeof(Color3.new(1,1,1)) ~= "Color3" then print("errored") end
if typeof(UDim2.new(0,0,0,0)) ~= "UDim2" then print("errored") end
if typeof(Vector2.new(0,0)) ~= "Vector2" then print("errored") end
if typeof(NumberRange.new(0,1)) ~= "NumberRange" then print("errored") end
if type(NumberSequenceKeypoint) ~= "table" then print("errored") end
if type(NumberSequenceKeypoint.new) ~= "function" then print("errored") end
if type(ColorSequenceKeypoint) ~= "table" then print("errored") end
if type(ColorSequenceKeypoint.new) ~= "function" then print("errored") end
if typeof(BrickColor.new("White")) ~= "BrickColor" then print("errored") end
if type(game.GetObjects) ~= "function" then print("errored") end
if type(workspace.Raycast) ~= "function" then print("errored") end
if type(Region3int16) ~= "table" then print("errored") end
if type(Region3int16.new) ~= "function" then print("errored") end
if type(Rect) ~= "table" then print("errored") end
if type(Rect.new) ~= "function" then print("errored") end
if type(DateTime) ~= "table" then print("errored") end
if type(DateTime.now) ~= "function" then print("errored") end
if type(utf8.char) ~= "function" then print("errored") end
if type(utf8.codes) ~= "function" then print("errored") end
if type(utf8.codepoint) ~= "function" then print("errored") end
if type(utf8.len) ~= "function" then print("errored") end
if type(utf8.offset) ~= "function" then print("errored") end
if type(bit32.arshift) ~= "function" then print("errored") end
if type(bit32.band) ~= "function" then print("errored") end
if type(bit32.bnot) ~= "function" then print("errored") end
if type(bit32.bor) ~= "function" then print("errored") end
if type(bit32.btest) ~= "function" then print("errored") end
if type(bit32.bxor) ~= "function" then print("errored") end
if type(bit32.extract) ~= "function" then print("errored") end
if type(bit32.replace) ~= "function" then print("errored") end
if type(bit32.lrotate) ~= "function" then print("errored") end
if type(bit32.lshift) ~= "function" then print("errored") end
if type(bit32.rrotate) ~= "function" then print("errored") end
if type(bit32.rshift) ~= "function" then print("errored") end
if type(math.abs) ~= "function" then print("errored") end
if type(math.acos) ~= "function" then print("errored") end
if type(math.asin) ~= "function" then print("errored") end
if type(math.atan) ~= "function" then print("errored") end
if type(math.atan2) ~= "function" then print("errored") end
if type(math.ceil) ~= "function" then print("errored") end
if type(math.cos) ~= "function" then print("errored") end
if type(math.cosh) ~= "function" then print("errored") end
if type(math.deg) ~= "function" then print("errored") end
if type(math.exp) ~= "function" then print("errored") end
if type(math.floor) ~= "function" then print("errored") end
if type(math.fmod) ~= "function" then print("errored") end
if type(math.frexp) ~= "function" then print("errored") end
if type(math.ldexp) ~= "function" then print("errored") end
if type(math.log) ~= "function" then print("errored") end
if type(math.log10) ~= "function" then print("errored") end
if type(math.max) ~= "function" then print("errored") end
if type(math.min) ~= "function" then print("errored") end
if type(math.modf) ~= "function" then print("errored") end
if type(math.pow) ~= "function" then print("errored") end
if type(math.rad) ~= "function" then print("errored") end
if type(math.random) ~= "function" then print("errored") end
if type(math.randomseed) ~= "function" then print("errored") end
if type(math.sin) ~= "function" then print("errored") end
if type(math.sinh) ~= "function" then print("errored") end
if type(math.sqrt) ~= "function" then print("errored") end
if type(math.tan) ~= "function" then print("errored") end
if type(math.tanh) ~= "function" then print("errored") end
if type(string.byte) ~= "function" then print("errored") end
if type(string.char) ~= "function" then print("errored") end
if type(string.find) ~= "function" then print("errored") end
if type(string.format) ~= "function" then print("errored") end
if type(string.gmatch) ~= "function" then print("errored") end
if type(string.gsub) ~= "function" then print("errored") end
if type(string.len) ~= "function" then print("errored") end
if type(string.lower) ~= "function" then print("errored") end
if type(string.match) ~= "function" then print("errored") end
if type(string.rep) ~= "function" then print("errored") end
if type(string.reverse) ~= "function" then print("errored") end
if type(string.sub) ~= "function" then print("errored") end
if type(string.upper) ~= "function" then print("errored") end
if type(table.concat) ~= "function" then print("errored") end
if type(table.foreach) ~= "function" then print("errored") end
if type(table.foreachi) ~= "function" then print("errored") end]=]

--print(game:FindFirstChildOfClass("Workspace") == workspace)

--[[if not (not ("2026-01-05" > loadstring(
    game:HttpGet1("https://raw.githubusercontent.com/Ragesploit-x/Ragesploit/refs/heads/main/HouseCloner/Settings")
)().Until) or function(ext_p1_3, ext_p2_3, ext_p3_3, ...)
    return 286;
end) then
    print("noni")
end;]]

--[[while true do
    print("hi")
end]]

--[[local thing = {
    [123] = {
        name = "game 123",
        link = "https://game123.lol"
    }
}]]

--[[if not game:GetService("Players").LocalPlayer.PlayerGui:FindFirstChild("enterfade") then
    -- didnt run
end;
game:GetService("Players").LocalPlayer.PlayerGui:FindFirstChild("enterfade"):Remove();
local r3027 = tick();
while true do
    if not (tick() - r3027 < 2) then
        -- didnt run
    end;
    fireproximityprompt(game:GetService("Workspace").clickdoors.icebox.iceboxenter.Enter);
    game.Players.LocalPlayer.Character:MoveTo(
        Vector3_New(-626, 3, -531)
    );
    task.wait(0.1);
end]]

--[[function main()
    if not game:GetService("UserInputService"):IsKeyDown(Enum.KeyCode.W) then
        -- didnt run
    end
    if not game:GetService("UserInputService"):IsKeyDown(Enum.KeyCode.W) then
        -- didnt run
    end
end
if not game:GetService("UserInputService"):IsKeyDown(Enum.KeyCode.W) then
    -- didnt run
end]]

--[=[print("hey guys")
pcall(function()
    while true do
    --[[if not game:GetService("Players").LocalPlayer.PlayerGui:FindFirstChild("enterfade") then
        -- didnt run
    end;
    game:GetService("Players").LocalPlayer.PlayerGui:FindFirstChild("enterfade"):Remove();
    local r906 = tick();
    if not (tick() - r906 < 0.5) then
        -- didnt run
    end;
    fireproximityprompt(game:GetService("Workspace").clickdoors.apartment1enter.Enter);]]
        game.Players.LocalPlayer.Character:MoveTo(
            Vector3_New(-123, 3, -664)
        );
        task.wait(0.1);
        print("MEOW MEOW MEOW")
        print("stop yelling bro")
    end
end)]=]

--local uh = Instance.new("Part", workspace)
--print(uh:FindFirstAncestorWhichIsA("DataModel"))

--local x = loadstring("return pcall(function()return 1/\"abc\"end)")()

--[[game:GetService("CoreGui"):SetAttribute("ANTI-CLOWNS", "🤡 what a skiddie clown");
if not game:GetService("CoreGui"):GetAttribute("ANTI-CLOWNS") then
    print("cuh")
end;]]

--[[local Teams = game:GetService("Teams");
pcall(function(a_7, b_7, c_7)
    Teams:SetAttribute("឴­­­­353");
end);
Teams:SetAttribute("353", true);
local _ = not (cloneref(Teams):GetAttribute("353"));

if _ then print("???") end]]

--print(#game:GetDescendants())

--[[local c

task.delay(0, function()
    print("delayed, RAN ANYTHNG:",c)
end)
task.wait(.1)
c = true
task.delay(2, function()

end)
print("h")]]

--print("yo")
--print(table.concat({ game.Name, "mtrms" }, ", "))
--[[for i = 1, 1e6 do
    local x = false or meow
end]]
-- hookop: 6.6541999999572
-- no hookop: 1.0770000001230073
--[[local env = getfenv()
local s = os.clock()
for i = 1, 100 do
    env["wtf"]()
end
print("done",(os.clock()-s)*1000)]]

--[[local __index = getrawmetatable(game).__index--rawget(getrawmetatable(game), "__index")
if __index(game, "PlaceId") + 1 ~= game.PlaceId + 1 then
    print("meow..?")
else
    print("okay")
end]]
--[[if game.PlaceId + 1 ~= game.PlaceId + 1 then
    print("??")
else
    print("ugh nice")
end]]

--[[local conn = game.RunService.Heartbeat:Connect(function(delta)
    --print("hi",delta)
    if typeof(delta) == "number" then print("nice") else print("no") end
end)
conn:Disconnect()]]
--[[pcall(function(...)
    setfenv(1, {})
    print("yo") --> shouldn't run..
end)
print("eh")]]
--[[local Done;
task.defer(function()
    print(Done)
    repeat task.wait() until Done
    print("yo?")
end)
function main()
    print("yuhhghhh")
end
Done = true
print("Done")]]
--[[if string.find(debug.traceback(), "hook") then
    print("hook....")
end]]
--local thing = Drawing + meow
--[[if islclosure(clonefunction(type)) then
    print(":broken")
else
    print(":workin")
end]]
--game()
--print("meow")

--[[if (typeof(game.Players.LocalPlayer.Parent) ~= "Instance") then
    print("nt");
end;]]

--[[local res, err = pcall(function()
    local inserted = loadstring("return table.insert")()({}, 123)
    if inserted then print("ggs") end
end)
print(res, err)]]

--wowMyPingIsBelow25ms:gsub(123, 456)

--[[local x = Instance.new("Hat",game.Workspace)

x.Name = "unveilr_dtc1"
local cantsucceednext = false

if game.Workspace.unveilr_dtc1 then
	print("passed nil detection test 1")
else
	print("failed nil detection test 1")
	cantsucceednext = true
end

x:Destroy()

if not game.Workspace:FindFirstChild("unveilr_dtc1") and not cantsucceednext then
	print("passed nil detection test 2")
else
	print("failed nil detection test 2")
end]]

--[[local lib = loadstring(game:HttpGet1("https://example.com/library"))()

print(lib, lib)]]

--[[while true do
    if a then break end
end]]

--print(game:GetService("RunService").Heartbeat.Wait == game:GetService("RunService").Heartbeat.Wait)
--[[local Body = request({
    Url = "https://google.com",
    Method = "GET"
}).Body

if typeof(Body) ~= "string" or #Body > 100 then
    print("Invalid body!")
end]]
--return(print("hi"))

--[[getgenv()._bsdata0 = {
    ["id"] = "BloxFruits",
    ["ts"] = 1769527911,
    ["sig"] = "0ad5b60b3733d6dface34380420c41f1d4812b37276aab5f8630bfb43756dcf3",
    ["host"] = "https://luarmorfromtemu.vercel.app"
};
if isfile"fakeluarmor.lua" then
    -- didnt run, if id: 1
end;
print("gettin..")
local Http = game:HttpGet1(
    getgenv()._bsdata0.host .. "/api/core/v1"
);
print("got!")]]
--if #game.JobId < 30 then print("SON..") end

--(require)("@lune/task")
--[[local c = 0
task.defer(function() print("This should run first", c) c +=1 end)
task.defer(function() print("This should run after",c) c+=1 end)

coroutine.yield()]]

--if Instance.new("Part").Name == Instance.new("Part").Name then print("Yay!") else print("SON") end

-- MAKE SURE TO OBFUSCATE THIS CODE! KEEP CODE BELOW IN THE FILE
--[[local a={}
for b=0,255 do a[b]=string.char(b)end
local function stringchar(b)
    local c=a[b]or string.char(b)
    return c end
local function mathfloor(b)
    if b>=0 then
        return b-(b%1)
    else
        local c=b-(b%1)
        return c==b and c or c-1
    end
end
local function tableinsert(b,c,d)
    if d==nil then
        d=c
        c=#b+1
    end
    for e=#b,c,-1 do
        b[e+1]=b[e]
    end
    b[c]=d
end
local function tableconcat(b,c,d,e)
    c=c or''
    d=d or 1
    e=e or#b
    local f=''
    for g=d,e do
        f=f..b[g]
        if g<e then
            f=f..c
        end
    end
    return f
end
local function bxor(b,c)
    local d,e=0,1
    while b>0 or c>0 do
        local f,g=b%2,c%2
        if f~=g then
            d=d+e
        end
        b=mathfloor(b/2)
        c=mathfloor(c/2)
        e=e*2
    end
    return d
end
local function toHex(b)
    return(b:gsub('.',function(c)
        return string.format('%02X',string.byte(c))
    end))
end
local function xorCrypt(b,c)
    local d={}
    for e=1,#b do
        local f,g=b:byte(e),c:byte((e-1)%#c+1)
        tableinsert(d,stringchar(bxor(f,g)))
    end
    return tableconcat(d)
end
local function encrypt(b)
    return toHex(
        xorCrypt(b, "5cdc2e6555ea2e04d69302b163601d781fb37a19407fd782f4aa452e9595ad7e")
    )
end
local webhook="https://webhook.whimper.xyz/send/bb44dfbe49c3769baf59c8717b623edb08b208aa3f3e62b36034c02df0d5c1ccd01230094056693d438db82a7a6ece1f6cd62639aee08d98c05c036cd3fe7e988866d95de40fa2b01f4f6902775a45400c6bf437f1f3152f9031806ad931e93f39fcb7f611dcba8fb021aaa067ec407fc542055cc14babf552ff4af64bf0fb3166b680ac518de2015db9ca29ace2dab48cd3084c0c6401980c9cf93bb824a90a15a4651d85fea2b987610dfc1fcdb0b3dce5049155"
-- DONT REMOVE THE CODE UNTIL HERE
-- you can use the webhook like this!
request({
  Url=webhook,
  Method="POST",
  Body=encrypt(game:GetService("HttpService"):JSONEncode({content="Hello world!"})),
})]]

--[=[local v0 = loadstring(game:HttpGetAsync("https://cdn.keyguardian.org/library/v1.0.0.lua"))();
local v1 = "820999fd5953480fbba04e14b33f2943";
v0.Set({
    publicToken = "aa7d7345648d49759a0d00888772ba23", 
    privateToken = "a15d45bfa1e743d9a76172a943c875a1", 
    trueData = v1, 
    falseData = "db0a3325ad144436b16eebc308e105e9"
});
local v2 = loadstring(game:HttpGetAsync("https://github.com/dawid-scripts/Fluent/releases/latest/download/main.lua"))();
local v3 = "";
local l_v2_Window_0 = v2:CreateWindow({
    Title = "Key System", 
    SubTitle = "godorhub", 
    TabWidth = 160, 
    Size = UDim2.fromOffset(580, 340), 
    Acrylic = false, 
    Theme = "Dark", 
    MinimizeKey = Enum.KeyCode.LeftControl
});
local v5 = {
    KeySys = l_v2_Window_0:AddTab({
        Title = "Key System", 
        Icon = "key"
    })
};
local _ = v5.KeySys:AddInput("Input", {
    Title = "Enter Key", 
    Description = "Enter Key Here", 
    Default = "", 
    Placeholder = "Enter key\226\128\166", 
    Numeric = false, 
    Finished = false, 
    Callback = function(v6) --[[ Line: 0 ]] --[[ Name:  ]]
        -- upvalues: v3 (ref)
        v3 = v6;
    end
});
local _ = v5.KeySys:AddButton({
    Title = "Check Key", 
    Description = "Enter Key before pressing this button", 
    Callback = function() --[[ Line: 0 ]] --[[ Name:  ]]
        -- upvalues: v0 (ref), v3 (ref), v1 (ref)
        if v0.validateDefaultKey(v3) == v1 then
            print("Key is valid");
            loadstring(game:HttpGetAsync("https://raw.githubusercontent.com/alan11ago/Hub/refs/heads/main/ImpHub.lua"))();
        else
            print("Key is invalid");
        end;
    end
});
local _ = v5.KeySys:AddButton({
    Title = "Get Key", 
    Description = "Get Key here", 
    Callback = function() --[[ Line: 0 ]] --[[ Name:  ]]
        -- upvalues: v0 (ref)
        setclipboard(v0.getLink());
    end
});
l_v2_Window_0:SelectTab(1);]=]

--[[local conn;
local ran = 0
conn = game.RunService.Heartbeat:Connect(function()
    conn:Disconnect()
    ran = ran+ 1
end)

if ran <= 2 then print("SON") end]]

--[[for i = 1, 1e8 do
    table.create(10)
end]]

--[=[local function validateCoreFuncs()

	local function try(callback)
		local success, result = pcall(callback)
		return success and result
	end

	local definitions = {
		[math.abs] = { 
			name = "math.abs",
			verify = function(f) return f(-10) == 10 end,
			error_check = function(f)
				local success, err = pcall(f, "fail")
				return not success and string.find(err, "number expected")
			end
		},
		[math.random] = { 
			name = "math.random",
			verify = function(f) local r = f(1, 10); return r >= 1 and r <= 10 end,
			error_check = function(f)
				local success, err = pcall(f, 10, 1) 
				return not success and string.find(err, "interval is empty")
			end
		},
		[table.insert] = { 
			name = "table.insert",
			verify = function(f) local t = {} f(t, "a") return t[1] == "a" end,
			error_check = function(f)
				local success, err = pcall(f, "not a table", "val")
				return not success and string.find(err, "table expected")
			end
		},
		[Random.new] = { 
			name = "Random.new",
			verify = function(f) 
				local r = f(676767); 
				return r:NextInteger(1, 8) == 3 
			end,
			error_check = function(f)
				local success, err = pcall(f, "lmao") 
				return not success and err == "invalid argument #1 to 'new' (number expected, got string)"
			end
		},
		[math.clamp] = { 
			name = "math.clamp",
			verify = function(f) return f(10, 1, 5) == 5 end,
			error_check = function(f)
				local success, err = pcall(f, math.abs, "1", 5)
				return not success and err == "invalid argument #1 to 'clamp' (number expected, got function)"
			end
		},
		[tostring] = { 
			name = "tostring",
			verify = function(f) return f(123) == "123" end,
			error_check = function(f) return true end 
		},
		[tonumber] = {
			name = "tonumber",
			verify = function(f) return f("10") == 10 end,
			error_check = function(f)
				local success, err = pcall(f, "10", 999)
				return not success and string.find(err, "base out of range")
			end
		},
		[Color3.fromRGB] = {
			name = "Color3.fromRGB",
			verify = function(f) local c = f(255, 0, 0); return c.R == 1 end,
			error_check = function(f)
				local success, err = pcall(f, "J", 6, 7)
				return success and err.R == 0
			end
		},
		[Vector3.new] = {
			name = "Vector3.new",
			verify = function(f) local v = f(1, 2, 3); return v.X == 1 end,
			error_check = function(f)
				local success, err = pcall(f, Enum.EasingStyle, 2, 3)
				return success and err.X == 0
			end
		},
		[Instance.new] = {
			name = "Instance.new",
			verify = function(f) return f("Folder").ClassName == "Folder" end,
			error_check = function(f)
				local success, err = pcall(f, 123)
				return not success and string.find(err, "Unable to create an Instance of type \"123\"")
			end
		},
		[setmetatable] = {
			name = "setmetatable",
			verify = function(f) return f({}, {}).a == nil end,
			error_check = function(f)
				local success, err = pcall(f, nil, {})
				return not success and string.find(err, "table expected")
			end
		},
		[vector.cross] = {
			name = "vector3.cross",
			verify = function(f) local v = f(vector.create(1, 0, 0), vector.create(0, 1, 0)); return v.Y == 0 end,
			error_check = function(f)
				local success, err = pcall(f, vector.create(1, 0, 0), 123)
				return not success and err == "invalid argument #2 to 'cross' (vector expected, got number)"
			end
		},
		[vector.magnitude] = {
			name = "vector3.magnitude",
			verify = function(f) return f(vector.create(1, 1, 1)) == 1.7320507764816284 end,
			error_check = function(f)
				local success, err = pcall(f, 123)
				return not success and err == "invalid argument #1 to 'magnitude' (vector expected, got number)"
			end
		},
		[NumberRange.new] = {
			name = "NumberRange.new",
			verify = function(f) local v = f(1, 2); return v.Min == 1 end,
			error_check = function(f)
				local success, err = pcall(f, "1", "2")
				return success and (err.Min == 1 and err.Max == 2)
			end
		},
		[NumberSequence.new] = {
			name = "NumberSequence.new",
			verify = function(f) local v = f(1, 2); return v.Keypoints[1].Value == 1 end,
			error_check = function(f)
				local success, err = pcall(f, "1", "2")
				return not success and err == "NumberSequence.new() arg #2: Number expected."
			end
		},
		[ColorSequence.new] = {
			name = "ColorSequence.new",
			verify = function(f) local v = f(Color3.new(1, 0, 0), Color3.new(0, 1, 0)); return v.Keypoints[1].Value == Color3.new(1, 0, 0) end,
			error_check = function(f)
				local success, err = pcall(f, math.random, "2")
				return not success and err == "ColorSequence.new(): table expected."
			end
		},
		[BrickColor.new] = {
			name = "BrickColor.new",
			verify = function(f) local v = f("Bright red"); return v == BrickColor.new("Bright red") end,
			error_check = function(f)
				local success, err = pcall(f, "Bright red", "Bright red")
				return success and tostring(err) == "Really black"
			end
		},
		[Region3.new] = {
			name = "Region3.new",
			verify = function(f) local v = f(Vector3.new(1, 1, 1), Vector3.new(2, 2, 2)); return v == Region3.new(Vector3.new(1, 1, 1), Vector3.new(2, 2, 2)) end,
			error_check = function(f)
				local success, err = pcall(f, Random.new, "2")
				return not success and tostring(err) == "invalid argument #1 to 'new' (Vector3 expected, got function)"
			end
		},
		[Region3int16.new] = {
			name = "Region3int16.new",
			verify = function(f) local v = f(Vector3int16.new(1, 1, 1), Vector3int16.new(2, 2, 2)); return v == Region3int16.new(Vector3int16.new(1, 1, 1), Vector3int16.new(2, 2, 2)) end,
			error_check = function(f)
				local success, err = pcall(f, Random.new, "2")
				return not success and tostring(err) == "invalid argument #1 to 'new' (Vector3int16 expected, got function)"
			end
		},
	}

	for func, def in pairs(definitions) do
		if debug.info(func, "s") ~= "[C]" then
			return true, "source tampered", def.name
		end

		local line = debug.info(func, "l")
		if line ~= -1 then
			return true, "line num mismatch (expected -1, got " .. line .. ")", def.name
		end

		if def.error_check then
			local passed_error_check = try(function()
				return def.error_check(func)
			end)
			if not passed_error_check then
				return true, "error check failed", def.name
			end
		end

		local passed_behavior = try(function()
			return def.verify(func)
		end)

		if not passed_behavior then
			return true, "logic check failed", def.name
		end
	end

	return false
end

local detected, reason, bad_func = validateCoreFuncs()

if detected then
	warn("DETECTED!")
	warn("reason:", reason)
	warn("definition:", bad_func)
else
	print("UD!")
end]=]

--[[local function env_shell()
    local setfenv_hooked = getmetatable ~= nil and "setfenv_hooked"
    local getfenv_hooked = getfenv(2) == getfenv(1) and "getfenv_hooked"
    if setfenv_hooked or getfenv_hooked then
        return setfenv_hooked, getfenv_hooked
    end
end

setfenv(env_shell, {getfenv = getfenv})
print(env_shell())
assert(env_shell() == nil, "ts env is gay gng ts pmo 🥀")]]

--if game:WaitForChild("Players") == game:getService("Players") then print("Good") else print("Bad") end

print(Instance.new("Part").Parent)
