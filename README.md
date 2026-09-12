# Custom Memory — 32 & 64-bit Process Memory Library for C# (+ Custom Functions)

> Thanks to `erfg12/memory.dll` for sharing publicly — this is a fork / extended version with added custom helpers.
>
> **Use responsibly and legally:** only use on your own processes, for debugging, learning Windows internals, or single-player modding where allowed. Do not use against protected online games — that violates their Terms of Service and can lead to bans. No anti-cheat bypass is included here.

Lightweight C# `memory` class for opening a process and reading / writing its memory via Win32 `ReadProcessMemory` / `WriteProcessMemory`, with pointer-chain resolver, AoB scanner, and freeze helpers. Works for 32-bit and 64-bit targets from a single `memory.cs`.

---

## ✨ Features

**Core:**
- `Initialize(processName)` — `GetProcessesByName` + `OpenProcess(0x1F0FFF)` + Wow64 / 64-bit detect + `MainModule`
- Single static instance: `memory.mem`
- `InitializeResult`: `Memeory_Successfully` / `Memeory_Failed`
- 32-bit (`GetCode`) + 64-bit (`Get64BitCode`) pointer paths, auto-selected via `Is64Bit`
- Address formats:
  - plain hex: `"1A2B3C"`
  - module + offset: `"Game.exe+1A2B3C"`, `"base+1A2B3C"`, `"main+..."`, `"client.dll+..."`
  - multi-level pointers: `"base+0x10,0x20,0x30"`, with `0x` prefix and negative `-` offsets supported

**Reading:**
- `READINT / READFLOAT / READSTRING` + `ReadInt / ReadFloat / ReadDouble / ReadLong / ReadByte / ReadBytes / ReadString`
- `ReadFloat(code, round=true)` rounds to 2 decimals by default
- `ReadString(code, length=32, zeroTerminated=true, encoding=UTF8)`

**Writing:**
- `WRITEMEMORY(address, type, value)` → `WriteMemory`
- Types: `float`, `int`, `byte`, `2bytes`, `bytes` (`"90 90"` or `"90,90"`), `double`, `long`, `string` (UTF8 or custom `Encoding`)
- Auto `VirtualProtectEx(ExecuteReadWrite)` → write → restore, `RemoveWriteProtection=true` by default
- `WriteBytes(UIntPtr, byte[])` direct
- `FREEZEVALUE / UNFREEZEVALUE` → `FreezeValue` loop every 25ms in background `Task` with `ConcurrentDictionary<string, CancellationTokenSource>`

**Scanning:**
- `AoBScan(start, end, search, readable, writable, executable, mapped)` — parallel `VirtualQueryEx` region walk + `CompareScan` + `FindPattern` with `??` / `?x` / `x?` masks
- `SyncAOBSCAN(start, end, search, offset)` sync wrapper, returns first hit as hex + offset

**Utils:**
- `ChangeProtection(code, newProtection, out old)` via `VirtualProtectEx`
- `GetModuleAddressByName(name)` via `Process.Modules`
- `LoadCode(name)` passthrough, `MSize()` → `"x16"` / `"x8"`
- `VirtualQueryEx` 32/64 wrappers, `NtQueryInformationThread`, `IsWow64Process`, full `MEM_*` / `PAGE_*` constants

---

## 🚀 Quick Start

### Requirements

- .NET Framework 4.x / .NET 6+ / .NET 8, AnyCPU or x64 (x64 recommended for 64-bit targets)
- Windows 10/11, run as admin if target needs it
- Single file: drop `memory.cs` into your project, no NuGet needed

### 1. Attach

```csharp
var init = memory.mem.Initialize("notepad");
if (init != memory.InitializeResult.Memeory_Successfully)
{
    Console.WriteLine("Process not found / open failed");
    return;
}
Console.WriteLine($"64-bit: {memory.mem.Is64Bit}, base: {memory.mem.MainModule.BaseAddress:X}");
```

Or with static helpers (uses `memory.mem` internally):

```csharp
memory.mem.Initialize("myapp");
int hp = memory.READINT("myapp.exe+0x123456,0x10,0x20");
```

### 2. Read / Write

```csharp
// static shortcuts
int   i = memory.READINT("base+0x1234");
float f = memory.READFLOAT("base+0x1234");
string s = memory.READSTRING("base+0x1234");

bool ok = memory.WRITEMEMORY("base+0x1234", "int", "100");
bool ok2 = memory.WRITEMEMORY("base+0x1234", "float", "99.5");
bool ok3 = memory.WRITEMEMORY("base+0x1234", "string", "hello");
bool ok4 = memory.WRITEMEMORY("base+0x1234", "bytes", "90 90 90");

// instance API for more control
memory.mem.WriteMemory("game.exe+0xABCD,0x10", "float", "1.5");
float v = memory.mem.ReadFloat("game.exe+0xABCD,0x10");
```

### 3. Pointers

```text
base+0x10                  -> MainModule + 0x10, dereferenced once if commas follow
my.dll+0x20,0x30,0x0       -> module base + 0x20 -> +0x30 -> +0x0
0x12345678                 -> absolute address
```

```csharp
UIntPtr addr = memory.mem.GetCode("base+0x10,0x20");
```

### 4. Freeze / Unfreeze

```csharp
memory.FREEZEVALUE("base+0x10", "int", "100");
Thread.Sleep(5000);
memory.UNFREEZEVALUE("base+0x10");
```

### 5. AoB Scan

```csharp
// async enumerable
var hits = await memory.mem.AoBScan(0, long.MaxValue, "48 8B ?? ?? ?? ?? 90", true, false, true, false);
foreach (long h in hits)
    Console.WriteLine(h.ToString("X"));

// sync first-hit + offset
string first = memory.SyncAOBSCAN(0, long.MaxValue, "90 90 ?? 48", 0x10);
Console.WriteLine(first);
```

Mask rules: `??` / `?` = wildcard byte, `1?` = high nibble only (`F0`), `?1` = low nibble only (`0F`).

---

## 📁 Project layout

```text
memory.cs   # everything: Process/Handle, Imports, Writing, Reading, AOBScan, GetCode/Get64BitCode
README.md
LICENSE     # GPL-3.0
```

No `.csproj` changes needed — compile `memory.cs` as `partial class memory` directly.

---

## ⚙️ API reference

| Method | Description |
|---|---|
| `Initialize(name)` | Attach to first `GetProcessesByName(name)` |
| `GetCode(name, size=8)` / `Get64BitCode(name, size=16)` | Resolve hex / module / pointer chain to `UIntPtr` |
| `ReadInt / ReadFloat / ReadDouble / ReadLong / ReadByte / ReadBytes / ReadString` | Typed RPM wrappers, `UIntPtr.Zero` / `<0x10000` guarded |
| `WriteMemory(code, type, value, encoding=null, RemoveWriteProtection=true)` | Typed WPM with protect swap |
| `FreezeValue / UnfreezeValue` | 25ms rewrite loop per address |
| `AoBScan / SyncAOBSCAN` | Region-filtered parallel signature scan |
| `ChangeProtection` | `VirtualProtectEx` helper |
| `GetModuleAddressByName` | `Process.Modules` lookup |

Return conventions: read failures → `0` / `""` / `null`, write → `bool`, init → `InitializeResult`.

---

## 🧨 Troubleshooting

**`Memeory_Failed`**
> Process name without `.exe` for `GetProcessesByName` (e.g. `"notepad"` not `"notepad.exe"`), process not running, or `OpenProcess` denied — retry as admin / x64.

**Reads return `0` / writes return `false`**
> `GetCode` returned `Zero` or `<0x10000` (bad module name, wrong offsets, ASLR shifted base). Print `GetCode(...)` first, verify module name case-insensitively, dump `MainModule.BaseAddress`.

**`bytes` type writes 1 byte**
> You passed `"90"` without space/comma — that's single-byte mode. Use `"90 90"` or `"90,90"` for arrays.

**Float parse fails on `,` locales**
> `WriteMemory` parses float with `InvariantCulture` — always pass `"99.5"` with dot.

**AoB scan slow / no hits**
> Narrow `start/end`, set `readable/writable/executable` correctly (`PAGE_EXECUTE_READ` counts as readable only if `readable=true`), check mask syntax (`??` with space-separated bytes).

---

## 🔒 Notes

- `OpenProcess(0x1F0FFF)` = `PROCESS_ALL_ACCESS` — over-privileged for just reading; consider `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` if you harden this.
- `FreezeValue` spawns one `Task` per address — unfreeze when done or you leak threads.
- `ReadProcessMemory` P/Invokes use `UIntPtr` sizes — pass 64-bit lengths correctly when targeting 64-bit.
- Original upstream: `erfg12/memory.dll` (MIT). This fork keeps GPL-3.0 per `LICENSE` — keep attribution.

---

## 🤝 Contributing

1. Fork, `git checkout -b feat/my-helper`
2. Keep 32 + 64-bit paths in sync (`GetCode` + `Get64BitCode`)
3. No new native deps — pure `kernel32` / `ntdll` P/Invoke only
4. PR with sample addresses against `notepad.exe` or your own test app, never against protected online games

---

## 📄 License

GPL-3.0 — see [LICENSE](LICENSE).

---

## 🙏 Credits

- `erfg12/memory.dll` — original public C# memory library this is based on
- Contributors to custom `SyncAOBSCAN`, `FREEZEVALUE`/`WRITEMEMORY` shortcuts and 64-bit fixes
