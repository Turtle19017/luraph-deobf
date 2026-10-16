-- roblox_shim.luau : globals the protected target may resolve dynamically.
-- Kept separate so the probe harness stays auditable.

local shim = {}

local function mk(name)
  return setmetatable({}, {
    __index = function(t, k)
      local f = function(...) return nil end
      rawset(t, k, f)
      return f
    end,
    __call = function() return nil end,
    __tostring = function() return name end,
  })
end

-- task.cancel / task.delay / task.spawn / task.wait ... (the `.cancel` site)
task = {
  cancel = function() return true end,
  delay = function() return 0 end,
  defer = function() return 0 end,
  spawn = function(f, ...) if type(f) == "function" then return f(...) end end,
  wait = function() return 0 end,
  desynchronize = function() end,
}

tick = 0
time = 0
elapsedTime = 0
-- os is readonly in Luau; os.clock already exists

Instance = { new = function(...) return mk("Instance") end }
game = mk("game")
workspace = mk("workspace")
script = mk("script")
shared = mk("shared")
UserSettings = mk("UserSettings")
RunService = mk("RunService")
Debris = mk("Debris")
plugin = mk("plugin")
settings = mk("settings")

local function deepShim(t, depth)
  if depth > 6 then return t end
  return setmetatable(t, {
    __index = function(_, k)
      local v = mk(tostring(k))
      rawset(t, k, v)
      return deepShim(v, depth + 1)
    end,
    __call = function() return nil end,
    __tostring = function() return "shim" end,
  })
end

-- _G is readonly in Luau, so rebind the globals directly.
game = deepShim(game, 1)
workspace = deepShim(workspace, 1)
Instance = deepShim(Instance, 1)
RunService = deepShim(RunService, 1)
Debris = deepShim(Debris, 1)
UserSettings = deepShim(UserSettings, 1)

return shim
