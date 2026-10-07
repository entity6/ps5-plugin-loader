# ploader 🎮

A PRX/SPRX injector for PS5.

⚠️ **Status:** Work in progress. May be unstable.

---

## 📋 Compatibility

|                        | Status     |
| ---------------------- | ---------- |
| **Firmware 11.60**     | ✅ Tested   |
| **Firmware 12.20**     | ✅ Tested   |
| **Firmware 12.70**     | ✅ Tested   |
| **Firmware 13.60**     | ✅ Tested   |
| **Other firmware**     | ❓ Untested |
| **PS4 games (PS4EMU)** | ✅ Tested   |
| **Native PS5 games**   | ❓ Untested |

> Compatibility may vary depending on the game, plugin, and firmware version.

---

## 🚀 Usage

1. Place your `.prx` or `.sprx` files on the console, for example:

   ```text
   /data/plugins/
   ```

2. Configure:

   ```text
   /data/plugins/ploader.toml
   ```

3. Send `ploader.elf`.

   Ploader will wait for a configured title to appear and automatically attempt to inject the configured plugins. ✨

4. Boot the configured game.

> You must re-send the payload every time you restart the game.

---

## ⚙️ Configuration

Ploader now uses a **TOML configuration file**:

```text
/data/plugins/ploader.toml
```

The configuration is divided into a global `[loader]` section and one or more `[[plugin]]` entries.

### 🧩 Basic Configuration

```toml
[loader]
timeout_s = 120
scan_existing = true
default_inject = true
default_restore_sandbox = true

[[plugin]]
title = "CUSA01234"
path = "/data/plugins/my_plugin.prx"
delay_ms = 0
inject = true
restore_sandbox = true
```

### 🎯 Multiple Plugins

You can define multiple `[[plugin]]` entries for the same title:

```toml
[loader]
timeout_s = 120
scan_existing = true
default_inject = true
default_restore_sandbox = true

[[plugin]]
title = "CUSA01234"
path = "/data/plugins/my_plugin.prx"
delay_ms = 0
inject = true
restore_sandbox = true

[[plugin]]
title = "CUSA01234"
path = "/data/plugins/my_other.sprx"
delay_ms = 5000
inject = true
restore_sandbox = true
```

You can also configure different titles:

```toml
[[plugin]]
title = "CUSA01234"
path = "/data/plugins/plugin_a.prx"
delay_ms = 0

[[plugin]]
title = "CUSA56789"
path = "/data/plugins/plugin_b.sprx"
delay_ms = 1000
```

---

## 🔧 Loader Options

### `timeout_s`

Maximum amount of time, in seconds, that ploader waits for configured titles.

```toml
[loader]
timeout_s = 120
```

Valid range:

```text
1 - 3600 seconds
```

The default is:

```text
120 seconds
```

---

### `scan_existing`

Controls whether existing processes are considered when ploader starts.

```toml
scan_existing = true
```

Possible values:

| Value   | Description                                           |
| ------- | ----------------------------------------------------- |
| `true`  | Enable scanning of existing processes                 |
| `false` | Only monitor processes appearing after ploader starts |

---

### `default_inject`

Controls whether plugins are enabled by default.

```toml
default_inject = true
```

A plugin can override this setting with its own `inject` value.

---

### `default_restore_sandbox`

Controls the default sandbox/credential restoration behavior.

```toml
default_restore_sandbox = true
```

A plugin can override this with its own `restore_sandbox` value.

---

## 🔌 Plugin Options

Each plugin uses a separate `[[plugin]]` section.

### `title`

The title ID of the target application.

```toml
title = "CUSA01234"
```

### `path`

Path to the `.prx` or `.sprx` plugin.

```toml
path = "/data/plugins/my_plugin.prx"
```

If a relative filename is provided, ploader automatically resolves it inside:

```text
/data/plugins/
```

For example:

```toml
path = "my_plugin.prx"
```

is resolved as:

```text
/data/plugins/my_plugin.prx
```

Full paths are also supported.

---

### `delay_ms`

Delay before attempting injection.

```toml
delay_ms = 5000
```

The value is specified in milliseconds.

Examples:

```text
0 ms     = immediately
1000 ms  = 1 second
5000 ms  = 5 seconds
60000 ms = 60 seconds
```

Valid range:

```text
0 - 3600000 ms
```

---

### `inject`

Controls whether the plugin should be injected.

```toml
inject = true
```

Possible values:

| Value   | Description             |
| ------- | ----------------------- |
| `true`  | Plugin will be injected |
| `false` | Plugin will be skipped  |

---

### `restore_sandbox`

Controls whether the target process credentials/sandbox state are restored after the injection attempt.

```toml
restore_sandbox = true
```

Possible values:

| Value   | Description                                          |
| ------- | ---------------------------------------------------- |
| `true`  | Restore the saved state after injection              |
| `false` | Keep the modified state after a successful injection |

> ⚠️ Only change this option if you understand the requirements of the plugin you are loading.

---

## 📝 Complete Example

A complete `ploader.toml` could look like this:

```toml
[loader]
timeout_s = 120
scan_existing = true
default_inject = true
default_restore_sandbox = true

# GTA V
[[plugin]]
title = "CUSA01234"
path = "/data/plugins/my_plugin.prx"
delay_ms = 0
inject = true
restore_sandbox = true

# Another plugin for the same title
[[plugin]]
title = "CUSA01234"
path = "/data/plugins/my_other.sprx"
delay_ms = 5000
inject = true
restore_sandbox = true

# Another game
[[plugin]]
title = "CUSA56789"
path = "/data/plugins/example.sprx"
delay_ms = 1000
inject = true
restore_sandbox = true
```

---

## 🔢 Injection Timing

The `delay_ms` option determines when ploader attempts the injection after the target process is detected.

| `delay_ms` | Timing     |
| ---------: | ---------- |
|        `0` | Immediate  |
|     `1000` | 1 second   |
|     `5000` | 5 seconds  |
|    `10000` | 10 seconds |
|    `60000` | 60 seconds |

> 💡 If a plugin does not work reliably with an immediate injection, try increasing `delay_ms`.

---

## 🔒 Behavior

* Ploader waits up to the configured `timeout_s` value for configured titles to appear.
* Only one instance of ploader can run at a time.
* A lock file is created at:

  ```text
  /data/plugins/ploader.lock
  ```
* If another active instance is detected, the new instance exits.
* Plugin paths without `/` are automatically resolved relative to:

  ```text
  /data/plugins/
  ```
* Each configured plugin can have its own delay and injection settings.
* Plugin configuration is loaded from:

  ```text
  /data/plugins/ploader.toml
  ```
* The target process state is restored according to `restore_sandbox`.

---

## 🛠️ Building

Ploader is built using the [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk).

Follow the SDK instructions to set up your development environment on WSL or native Linux, then run:

```sh
make
```

Prebuilt releases are available in the **Releases** section.

---

## 🔧 Technical Notes

* Uses `ptrace`-based process manipulation to perform the module loading operation inside the target process.
* Temporarily adjusts the target process environment required for module loading.
* Saves the relevant process state before injection.
* Restores the saved state according to the configured `restore_sandbox` option.
* Allocates temporary memory in the target process for the injection routine.
* Temporary memory is released after the operation.
* Does not patch `eboot.bin`.
* Logging is currently disabled by default.

---

## 🐛 Troubleshooting

### Plugin does not load

Check that the plugin exists at the configured path:

```text
/data/plugins/
```

For example:

```text
/data/plugins/my_plugin.prx
```

Also verify the title ID:

```toml
title = "CUSA01234"
```

and make sure it exactly matches the target application.

### Plugin needs more time to initialize

Try increasing the delay:

```toml
delay_ms = 5000
```

or:

```toml
delay_ms = 10000
```

### Ploader exits immediately

Check whether another instance is already running.

The lock file is:

```text
/data/plugins/ploader.lock
```

Ploader automatically checks whether the process associated with the lock is still alive.

---

## 🙏 Credits

Built using the [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk).

Inspired by and referenced from:

* [GoldHEN](https://github.com/GoldHEN/GoldHEN)
* [etaHEN](https://github.com/LightningMods/etaHEN)
* [elfldr](https://github.com/ps5-payload-dev/elfldr)

---

## ⚠️ Disclaimer

Use at your own risk. Compatibility and stability are not guaranteed.

This project is intended for educational and homebrew purposes only.
