# mckill

eBPF tool that detects Minecraft Java client processes and sends them `SIGSEGV`.

On load it:

1. Attaches BPF programs for `exec`, syscall enter, and process exit.
2. Scans `/proc/*/cmdline` for already-running Minecraft Java clients.
3. Pins the links under `/sys/fs/bpf/mckill` so they survive the userspace process exiting.

Flagged PIDs are killed on their next syscall; exited PIDs are cleaned out of the map.

## Requirements

- Linux kernel with BTF (`/sys/kernel/btf/vmlinux`)
- Root (CAP_BPF / CAP_SYS_ADMIN) to load and pin programs
- Build deps: `clang`, `llvm`, `libbpf`, `bpftool`, `python3`

On Arch/CachyOS roughly:

```bash
sudo pacman -S clang llvm libbpf bpf bpftool
```

## Build

```bash
make
```

This generates `vmlinux.h`, compiles the BPF object, builds the libbpf skeleton, then links the userspace binary `mckill`.

```bash
make clean   # remove generated files and the binary
```

## Usage

```bash
# load + pin (detaches userspace after arming)
sudo ./mckill

# unload pinned programs
sudo ./mckill unload
```

Pinned paths:

| Pin                            | Program                                            |
| ------------------------------ | -------------------------------------------------- |
| `/sys/fs/bpf/mckill/exec`    | `sched_process_exec` — mark new MC Java clients |
| `/sys/fs/bpf/mckill/syscall` | `sys_enter` — SIGSEGV flagged PIDs              |
| `/sys/fs/bpf/mckill/exit`    | `sched_process_exit` — drop dead PIDs           |

## Detection

A process is treated as a Minecraft Java client when argv0 is `java` (or ends with `/java`) **and** the cmdline matches one of:

**Strong** (any one):

- `-Dminecraft.client.jar=`
- `net.fabricmc.loader.impl.launch.knot.KnotClient`
- `org.quiltmc.loader.impl.launch.knot.KnotClient`
- `net.minecraft.client.main.Main`
- `net.minecraft.launchwrapper.Launch`
- `cpw.mods.modlauncher.Launcher`

**Branded launcher** (all of):

- `-Dminecraft.launcher.brand=`
- `--gameDir`
- `--assetsDir`

**Layout** (all of):

- `.minecraft/`
- `--gameDir`
- `--assetsDir`
- `--assetIndex`
- `--versionType`

## Source layout

| File               | Role                                                |
| ------------------ | --------------------------------------------------- |
| `mckill.bpf.c`   | BPF programs + marker matching                      |
| `mckill.c`       | userspace loader,`/proc` scan, pin/unload         |
| `scrub_paths.py` | zero residual source-path strings in the BPF object |
| `Makefile`       | build pipeline                                      |
