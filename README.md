<img width="500" height="500" alt="emblem-debian-white" src="https://github.com/user-attachments/assets/6ef8eb64-5ca4-4f19-908e-b746acc7dec1" />


# Arvor Linux : When Atomicity Meets Mutability.
ARM Readme:https://github.com/NextFerret/arvor/blob/main/README-ARM.md

**Arvor Linux** is a Debian-based Linux distribution designed to provide **atomic system updates without relying on an immutable root filesystem**.

Unlike many modern atomic distributions, Arvor separates the concepts of **atomicity** and **immutability**. The project focuses on reliable, transactional upgrades while preserving a traditional, fully mutable Linux environment.

---

# Atomic ≠ Immutable

These terms are often used interchangeably, but they describe different concepts.

## Atomicity

**Atomicity** is the property of an operation that either:

- completes successfully; or
- does not happen at all.

No partially applied state is ever exposed.

Examples:

- Transactional database commits
- Transactional operating system updates

Atomicity prevents incomplete upgrades from leaving the system in an inconsistent state.

---

## Immutability

**Immutability** means an object or filesystem cannot be modified after it has been created.

Examples include:

- Read-only root filesystems
- OSTree deployments
- Container image layers

Immutability is one possible implementation strategy for atomic updates, but **it is not a requirement**.

---

## Arvor's Approach

Arvor provides atomic upgrades while maintaining a traditional mutable Linux system.

Instead of using technologies such as:

- OverlayFS
- OSTree
- Read-only root filesystems

Arvor relies on:

- LVM snapshots
- Transactional package operations
- Rollback support
- Native Debian compatibility

The result is a system that remains familiar to Linux administrators while providing recovery from failed upgrades.

---

# Core Components

| Component | Description |
|----------|-------------|
| **arvorctl** | Central CLI for inspecting boot health, managing atomic A/B/C rotation slots, inspecting diffs, and triggering instant rollbacks. |
| **arvor-guard** | Proactive Thin Pool storage guardian service that prevents out-of-space lockups by auto-cleaning stale snapshots. |
| **napt** | High-performance C++ transactional package manager with multithreading, package redirection (`replaces=`), and pre-transaction snapshots. |
| **nsm** | Snapshot Manager responsible for creating, managing and restoring system snapshots. |
| **nlc** | Lightweight chroot environment manager used internally by Arvor. |

---

# Atomic System Control (`arvorctl`) & A/B/C Boot Protection

Arvor features an autonomous **A/B/C Thin LVM snapshot lifecycle** integrated into the `initramfs` and `systemd`, preventing unbootable systems caused by faulty upgrades, bad kernels, or power losses.

### How A/B/C Protection Works:
* **Slot A (`root`)**: The live, mutable root partition currently in execution.
* **Slot B (`root_b`)**: Snapshot of the last known stable boot state.
* **Slot C (`root_c`)**: Snapshot of the second-to-last stable boot state (fallback).

1. **On Successful Boot**: When `systemd` reaches multi-user target, `arvor-boot-success` tags the volume as healthy. During the next boot, `initramfs` rotates `root_b -> root_c` and establishes a fresh `root_b` snapshot.
2. **On Boot Failure (Crash / Kernel Panic / Hang)**: If the system fails to validate boot health, `initramfs` detects the missing `boot_ok` marker, emits a Plymouth visual alert, and **automatically merges `root_b` (or `root_c`) back into `root`**, restoring system functionality without user intervention.
3. **GRUB Recovery Menu**: Snapshots are also automatically exposed in the GRUB bootloader under the *Atomic Recovery Snapshots* submenu for manual rescue selection.
4. **Thin Pool Space Guardian (`arvor-guard`)**: Runs in the background (`arvor-guard.timer`) monitoring pool occupancy. If data exceeds 85%, it automatically purges oldest auto-snapshots to prevent root filesystems from locking up in read-only mode.

### Managing Snapshots with `arvorctl`
The `arvorctl` CLI allows users to inspect system health, trigger rollbacks, inspect file differences, and manage snapshots on demand:

```bash
# Check atomic boot health and inspect A/B/C snapshot slots
arvorctl status

# Compare file differences between active live system and a snapshot
arvorctl diff b
arvorctl diff c

# Create an instantaneous manual snapshot of the root filesystem
arvorctl snapshot [name]

# Manually rollback to Slot B (last stable state) or Slot C
arvorctl rollback b
arvorctl rollback c

# Manually validate and mark current boot as healthy
arvorctl mark-ok
```

---

# Package Manager (`napt`)

`napt` is Arvor's C++ transactional package manager with built-in multi-threading and security hardening.

### Key Features
- **Parallel Downloads**: Multi-threaded metadata sync and `.deb` batch downloading.
- **Repository Package Redirection (`replaces=`)**: Seamlessly redirects and downloads native Arvor packages when upstream Debian packages are superseded by repository rules.
- **Pre-Transaction Snapshot Protection**: Automatically secures host state before applying package transactions with rollback capability.
- **Running Kernel Modules Preservation**: Caches `/lib/modules/$(uname -r)` during kernel updates to prevent running driver failures before reboot.
- **Smart Cache Cleanup (`autoclean`)**: Purges stale packages from `/etc/napt/cache` while retaining active ones:
  ```bash
  napt autoclean
  ```
- **Security & Integrity**: Strict SHA256 checksum enforcement, path traversal protection, and cURL option injection mitigation.
- **Real-Time Size Feedback**: Displays file sizes dynamically in KB and MB.

### Common Commands
- `napt sync` - Refresh repository metadata concurrently.
- `napt install <pkg>` - Install packages (chroot-verified before host application).
- `napt upgrade` - Upgrade installed packages transactionally.
- `napt rollback` - Revert the last package operation using pre-transaction snapshot.
- `napt info <pkg>` - Display detailed repository origin, version, SHA256, and replacement rules.
- `napt why <pkg>` - Explain why a package is installed with reverse dependency tree.
- `napt depends <pkg>` - List forward dependencies (Depends, Recommends, Suggests).
- `napt list` - List all currently installed packages on the system.
- `napt stats` - Show cache metrics, repository stats, and package footprint.
- `napt history` - View past installation, upgrade, and removal logs.
- `napt clean` - Clear the entire package cache.
- `napt autoclean` - Remove obsolete cached package files and free disk space.

---

# System Requirements

Minimum requirements:

- **CPU:** Any x86_64 processor from approximately the last 15 years
- **Memory:** 4 GB RAM
- **Storage:** 32 GB available disk space

Recommended:

- SSD
- 8 GB RAM or more

---

# Architecture

Arvor intentionally avoids technologies commonly used by immutable distributions.

| Technology | Used |
|-----------|------|
| OverlayFS | ❌ |
| OSTree | ❌ |
| Read-only root filesystem | ❌ |
| LVM Snapshots | ✅ |
| Mutable root filesystem | ✅ |
| Transactional updates | ✅ |

---

# Frequently Asked Questions

## Does Arvor use OverlayFS?

No.

Arvor intentionally avoids OverlayFS due to its long history of privilege escalation vulnerabilities and because it does not fit the project's design goals.

---

## Does Arvor use OSTree?

No.

Arvor implements its own transactional update model.

---

## Is the system immutable?

No.

Arvor is fully mutable while still supporting atomic upgrades and rollbacks.

---

## Is Arvor written entirely in Python?

No.

Earlier releases relied heavily on Python.

Beginning with **Arvor 2.1**, the **Project Xesta** initiative migrated most core utilities to **C and C++** to improve performance, reduce runtime dependencies and simplify distribution.

---

## What happened to NF-Tree?

**NF-Tree** was Arvor's original snapshot manager based on Btrfs.

During the development of Arvor 2.1, it was replaced by **NSM (NextFerret Snapshot Manager)** after a major redesign of the snapshot infrastructure.

NSM provides a cleaner architecture and serves as the foundation for future releases.

---

# License

**Software Cujo Código é Aberto (SCCA)**

Copyright © NextFerret

Licensed under the **Arvor License v1**.
