# ploader

A PRX/SPRX injector for PS5.

**Status:** works on **`CUSAxxxxx`** titles. **`PPSAxxxxx`** titles are not
supported yet.

---

## Usage

1. Put your plugins in `/data/plugins/`.
2. Edit `/data/plugins/ploader.toml`.
3. Send `ploader.elf` and boot the game, plugins inject automatically.
4. Re-send the payload every time you restart the game.

## Configuration (`ploader.toml`)

```toml
[loader]
timeout_s = 60
expose_data = true

[[plugin]]
title = "CUSA01234"
path = "myplugin.sprx"
delay_ms = 1000
inject = true
main_thread = false

[[plugin]]
title = "CUSA56789"
path = "myplugin2.sprx"
delay_ms = 1000
inject = true
main_thread = true
```

### `[loader]` options

| Option        | Default | Description                                        |
| ------------- | ------- | -------------------------------------------------- |
| `timeout_s`   | `60`   | Seconds to wait for a title (1–3600).               |
| `delay_ms`    | `1000`  | Default plugin delay in ms (0–60000).              |
| `debug_log`   | `false`  | Write `/data/plugins/ploader.log`.                |
| `console_log` | `false` | Print log lines to the terminal.                   |
| `expose_data` | `false` | Bind-mount `/data` into the game's sandbox.        |

> Keep `expose_data = true` for plugins that read files, without it they fall
> back to a default/disabled state.

### `[[plugin]]` options

| Option        | Default | Description                                                        |
| ------------- | ------- | ------------------------------------------------------------------ |
| `title`       | (none)  | Title ID (`CUSAxxxxx`) or `*` for all titles.                      |
| `path`        | (none)  | `.prx`/`.sprx` path (relative names go to `/data/plugins/`).       |
| `delay_ms`    | loader  | Delay before injection (0–60000).                                  |
| `inject`      | `true`  | `false` skips the plugin.                                          |
| `main_thread` | `false` | Load on the game's main thread.                                    |

---

## Troubleshooting

| Problem | Fix |
| ------- | --- |
| Plugin not loading | Check the `path` and the exact `title` ID. |
| Can't use `/data` / plugin falls back to defaults | Set `expose_data = true`; the log should show `bind: /data mounted at /mnt/sandbox/<TITLE>_xxx/data`. |
| Plugin needs UI or login flow | Set `main_thread = true`; the log shows `main: hijacking rip=...`. Note the load is synchronous, the game freezes until the plugin's init returns. |
| Injection too early | Increase `delay_ms`. |
| ploader exits immediately | Another instance is running, check `/data/plugins/ploader.lock`. |

---

## Technical details

The injection sequence:

1. **Detect** the running title and wait for the game image to be ready
   (`eboot.bin` + main module mapped).
2. **Expose `/data`:** mount `/data` into the exact sandbox instance of that
   game (`/proc/<pid>/root`, e.g. `/mnt/sandbox/CUSA01234_022/data`) as a
   `nullfs` mirror. The game's `rootdir`/`jaildir` are never changed, so saves
   stay intact.
3. **Inject** on `ready + delay_ms`:
   - `main_thread = true`: the process is stopped (`PT_ATTACH`) and the main
     thread's `rip`/`rdi` are redirected to a stub that calls
     `sceKernelLoadStartModule`. The load is synchronous, no private stack,
     no xstate.
   - `main_thread = false`: a remote loader thread arms `pthread_create` and
     the game keeps running while the plugin starts (asynchronous and more stable).

Files created at runtime:

```text
/data/plugins/ploader.log   (debug log)
/data/plugins/ploader.lock  (single-instance lock)
```

**Build:** `make`, requires the [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk).

---

## References

* [etaHEN](https://github.com/LightningMods/etaHEN)
* [elfldr](https://github.com/ps5-payload-dev/elfldr)

Use at your own risk. For educational and homebrew purposes only.