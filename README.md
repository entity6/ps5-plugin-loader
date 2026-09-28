# ploader 🎮

A PRX/SPRX injector for PS5.

⚠️ **Status:** Work in progress. May be unstable.

---

## 📋 Compatibility

| | Status |
|---|---|
| **Firmware 11.60** | ✅ Tested |
| **Firmware 12.20** | ✅ Tested |
| **Other firmware** | ❓ Untested |
| **PS4 games (PS4EMU)** | ✅ Tested |
| **Native PS5 games** | ❓ Untested |

---

## 🚀 Usage

1. Place your `.prx` or `.sprx` files on the console (e.g. `/data/plugins/`)
2. Configure `/data/plugins/ploader.ini` (see below)
3. Send `ploader.elf` - ploader will wait for the game to appear and inject automatically ✨
4. Boot the game

> You must re-send the payload every time you restart the game.

---

## ⚙️ Configuration

Edit `/data/plugins/ploader.ini`:

```ini
[CUSA01234]
/data/plugins/my_plugin00.prx = 0  ; Disabled - won't inject.
/data/plugins/my_plugin01.prx = 1  ; Early - kicks in as soon as the process starts loading.
/data/plugins/my_plugin02.prx = 2  ; Late  - waits for the game to be fully loaded.

[CUSA56789]
my_plugin.prx   = 1  ; Short name - resolved to /data/plugins/my_plugin.prx automatically.
my_other.sprx   = 2
```

### 🔢 Injection Modes

| Value | Mode | Description |
|-------|------|-------------|
| `0` | Disabled | Plugin is skipped entirely |
| `1` | Early 🟡 | Injects while the game is still loading - use for plugins that need to be there from the start |
| `2` | Late 🟢 | Waits for the game to be fully loaded - safer, more stable |

> 💡 **Tip:** If you're unsure which mode to use, start with `2`. Use `1` only if the plugin needs to hook something early in the load process.

> 💡 **Tip:** If no `/` is in the name, ploader automatically looks in `/data/plugins/`. Full paths are also accepted.

### 🔒 Behavior

- ploader waits up to **120 seconds** for each configured title to appear before giving up.
- Only **one instance** of ploader can run at a time - if another is already active, the new one exits immediately.
- Process credentials are **saved before** injection and **fully restored after**, leaving the game process clean. 🧹

---

## 🔨 Building

Ploader is built using the [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk).  
Follow the SDK instructions to set up your environment on WSL or native Linux, then:

```sh
make
```

Prebuilt releases are available in the [Releases](../../releases) section.

---

## 🔧 Technical Notes

- Uses **ptrace thread hijacking** to call `sceKernelLoadStartModule` inside the target process.
- Temporarily sets the process `rootdir`/`jaildir` to the kernel root vnode so it can see the full filesystem, then **restores original credentials** after injection.
- Allocates a temporary **RW page** in the target process memory for the shellcode trampoline, freed after use.
- Does **not** patch `eboot.bin`.

---

## 🙏 Credits

Built using the [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk).

Inspired by and referenced from:
- [GoldHEN](https://github.com/GoldHEN/GoldHEN)
- [etaHEN](https://github.com/LightningMods/etaHEN)
- [ps5-payload-dev/elfldr](https://github.com/ps5-payload-dev/elfldr)

---

## ⚠️ Disclaimer

Use at your own risk. Compatibility and stability are not guaranteed.  
This project is intended for educational and homebrew purposes only.