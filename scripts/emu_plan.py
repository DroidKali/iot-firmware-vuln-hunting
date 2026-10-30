#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""emu_plan.py — 整机仿真启动计划（只读探测，不执行 QEMU）

M4 的第一半：把「这个 rootfs 能不能被 QEMU 整机启动、需要什么参数、缺什么」
写成一份可复核的计划。它只读文件、解析 ELF / 内核头 / ext2 超级块，不启动
QEMU、不执行固件字节、不调用外部命令。

计划里的 qemu.argv 使用容器内路径：/firmware/... 与 /out/serial.log。
执行由 emu_run.py 交给 sandbox_run.py 完成；本工具不负责构建镜像，只给出
build.commands 并标明镜像是否已经存在。

用法
----
    python scripts/emu_plan.py --rootfs /path/to/rootfs --json plan.json
    python scripts/emu_plan.py --rootfs rootfs --kernel boot/vmlinux \
        --image-out rootfs.img --network user --hostfwd tcp:127.0.0.1:8080-:80

退出码：0 计划可执行（ready）；1 存在阻断项（blocked）；2 用法/IO 错误。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

VERSION = "1.0"
SCHEMA = "emulation-plan/1.0"
TOOL = "emu_plan.py"

EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_USAGE = 2
FENCE = chr(96) * 3

#: 每种目标架构对应的 QEMU 组合。这张表是方法论 §6.1 的可执行版本；
#: 任何一项改动都必须同时改文档与 selftest，不能只在代码里漂移。
ARCH = {
    "mips": {
        "qemu": "qemu-system-mips", "machine": "malta", "kernel": "vmlinux",
        "disk": "ide", "root": "/dev/sda", "console": "ttyS0",
        "net": "e1000", "cpu": None,
    },
    "mipsel": {
        "qemu": "qemu-system-mipsel", "machine": "malta", "kernel": "vmlinux",
        "disk": "ide", "root": "/dev/sda", "console": "ttyS0",
        "net": "e1000", "cpu": None,
    },
    "mips64": {
        "qemu": "qemu-system-mips64", "machine": "malta", "kernel": "vmlinux",
        "disk": "ide", "root": "/dev/sda", "console": "ttyS0",
        "net": "e1000", "cpu": None,
    },
    "mips64el": {
        "qemu": "qemu-system-mips64el", "machine": "malta", "kernel": "vmlinux",
        "disk": "ide", "root": "/dev/sda", "console": "ttyS0",
        "net": "e1000", "cpu": None,
    },
    "arm": {
        "qemu": "qemu-system-arm", "machine": "virt", "kernel": "zImage",
        "disk": "virtio", "root": "/dev/vda", "console": "ttyAMA0",
        "net": "virtio-net-device", "cpu": "cortex-a15",
    },
    "aarch64": {
        "qemu": "qemu-system-aarch64", "machine": "virt", "kernel": "Image",
        "disk": "virtio", "root": "/dev/vda", "console": "ttyAMA0",
        "net": "virtio-net-device", "cpu": "cortex-a57",
    },
    "i386": {
        "qemu": "qemu-system-i386", "machine": "pc", "kernel": "bzImage",
        "disk": "ide", "root": "/dev/sda", "console": "ttyS0",
        "net": "e1000", "cpu": None,
    },
    "x86_64": {
        "qemu": "qemu-system-x86_64", "machine": "pc", "kernel": "bzImage",
        "disk": "ide", "root": "/dev/sda", "console": "ttyS0",
        "net": "e1000", "cpu": None,
    },
}

INIT_CANDIDATES = ("/sbin/init", "/etc/init.d/rcS", "/linuxrc", "/init", "/bin/sh")
KERNEL_NAMES = ("vmlinux", "zImage", "bzImage", "Image")
MAX_ELF_SCAN = 400
MAX_ELF_READ = 64 * 1024

MACHINE_NAMES = {
    3: ("i386", 32), 8: ("mips", None), 20: ("ppc", 32), 21: ("ppc64", 64),
    40: ("arm", 32), 62: ("x86_64", 64), 183: ("aarch64", 64),
    243: ("riscv64", 64),
}
MIPS_ABI = {0x1000: "o32", 0x2000: "n32", 0x4000: "n64", 0x8000: "eabi32"}


class UsageError(Exception):
    """参数/输入错误；main 捕获后退出 2。"""


def _force_utf8_io() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError, OSError):
            pass


def _say(msg: str = "", stream: Any = None) -> None:
    out = stream if stream is not None else sys.stdout
    try:
        print(msg, file=out)
    except UnicodeEncodeError:
        enc = getattr(out, "encoding", None) or "utf-8"
        print(msg.encode(enc, "replace").decode(enc, "replace"), file=out)


def _write_json(path: str, obj: Any) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")


def _write_text(path: str, text: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def sha256_file(path: str) -> Optional[str]:
    if not _is_regular(path):
        return None
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for blk in iter(lambda: fh.read(1 << 20), b""):
                h.update(blk)
    except OSError:
        return None
    return h.hexdigest()


def _is_regular(path: str) -> bool:
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        return False


def _is_link(path: str) -> bool:
    try:
        if os.path.islink(path):
            return True
        if os.name == "nt":
            st = os.stat(path, follow_symlinks=False)
            return bool(getattr(st, "st_file_attributes", 0) & 0x400)
    except (OSError, AttributeError):
        return False
    return False


def _rel_mount(path: str, root: str, prefix: str) -> str:
    rel = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
    rel = rel.replace(os.sep, "/")
    if rel == ".":
        return prefix
    return prefix.rstrip("/") + "/" + rel.lstrip("/")


def _inside(path: str, root: str) -> bool:
    p = os.path.normcase(os.path.realpath(os.path.abspath(path)))
    r = os.path.normcase(os.path.realpath(os.path.abspath(root)))
    return p == r or p.startswith(r + os.sep)


def _dir_summary(root: str, do_hash: bool = True) -> Dict[str, Any]:
    """统计 rootfs 并给清单哈希；不跟随符号链接、不读特殊文件。"""
    files = 0
    total = 0
    rows: List[Tuple[str, str]] = []
    notes: List[str] = []
    unreadable: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        dirnames[:] = [d for d in dirnames
                       if not _is_link(os.path.join(dirpath, d))]
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            if _is_link(full):
                continue
            try:
                st = os.stat(full)
            except OSError:
                unreadable.append(rel)
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            files += 1
            total += int(st.st_size)
            if do_hash:
                digest = sha256_file(full)
                if digest is None:
                    unreadable.append(rel)
                else:
                    rows.append((rel, digest))
    if unreadable:
        notes.append("有 %d 个文件无法读取，清单哈希不可信：%s"
                     % (len(unreadable), "、".join(unreadable[:5])))
    digest = None
    if do_hash and not unreadable:
        h = hashlib.sha256()
        for rel, row_digest in sorted(rows):
            h.update(rel.encode("utf-8") + b"\x00" + row_digest.encode("ascii") + b"\n")
        digest = h.hexdigest()
    return {"files": files, "bytes": total, "sha256": digest,
            "notes": notes}


def _read(path: str, size: int) -> Optional[bytes]:
    # rootfs 里的 /dev/console 等字符设备会阻塞 read；只读普通文件。
    if not _is_regular(path):
        return None
    try:
        with open(path, "rb") as fh:
            return fh.read(size)
    except OSError:
        return None


def _u16(data: bytes, off: int, endian: str) -> int:
    return struct.unpack_from(endian + "H", data, off)[0]


def _u32(data: bytes, off: int, endian: str) -> int:
    return struct.unpack_from(endian + "I", data, off)[0]


def _u64(data: bytes, off: int, endian: str) -> int:
    return struct.unpack_from(endian + "Q", data, off)[0]


def parse_elf(path: str) -> Optional[Dict[str, Any]]:
    """只读 ELF 头与 PT_INTERP；不依赖 readelf/file。"""
    head = _read(path, 64)
    if not head or len(head) < 52 or head[:4] != b"\x7fELF":
        return None
    cls, data_enc = head[4], head[5]
    if cls not in (1, 2) or data_enc not in (1, 2):
        return None
    endian = "<" if data_enc == 1 else ">"
    bits = 32 if cls == 1 else 64
    try:
        e_type = _u16(head, 16, endian)
        e_machine = _u16(head, 18, endian)
        if cls == 1:
            phoff = _u32(head, 28, endian)
            flags = _u32(head, 36, endian)
            phentsize = _u16(head, 42, endian)
            phnum = _u16(head, 44, endian)
        else:
            phoff = _u64(head, 32, endian)
            flags = _u32(head, 48, endian)
            phentsize = _u16(head, 54, endian)
            phnum = _u16(head, 56, endian)
    except (struct.error, IndexError):
        return None
    interp = None
    if phoff and phentsize >= (32 if cls == 1 else 56) and phnum:
        try:
            with open(path, "rb") as fh:
                for i in range(min(int(phnum), 128)):
                    fh.seek(int(phoff) + i * int(phentsize))
                    ph = fh.read(56)
                    if len(ph) < (32 if cls == 1 else 56):
                        break
                    p_type = _u32(ph, 0, endian)
                    if p_type != 3:  # PT_INTERP
                        continue
                    if cls == 1:
                        p_offset = _u32(ph, 4, endian)
                        p_filesz = _u32(ph, 16, endian)
                    else:
                        p_offset = _u64(ph, 8, endian)
                        p_filesz = _u64(ph, 32, endian)
                    ph = b""
                    if p_offset and p_filesz:
                        fh.seek(int(p_offset))
                        raw = fh.read(min(int(p_filesz), 4096))
                        interp = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
                    break
        except (OSError, struct.error):
            pass
    return {
        "bits": bits, "endian": "little" if data_enc == 1 else "big",
        "e_type": e_type, "e_machine": e_machine, "e_flags": flags,
        "interp": interp,
        "arch": _arch_from_elf(e_machine, bits, data_enc),
    }


def _arch_from_elf(machine: int, bits: int, data_enc: int) -> Optional[str]:
    if machine == 8:
        suffix = "64" if bits == 64 else ""
        return "mips" + suffix + ("el" if data_enc == 1 else "")
    if machine == 3:
        return "i386"
    if machine == 62:
        return "x86_64"
    if machine == 40:
        return "arm"
    if machine == 183:
        return "aarch64"
    if machine in (20, 21):
        return "ppc" if machine == 20 else "ppc64"
    if machine == 243:
        return "riscv64"
    return None


def _mips_abi(flags: int) -> Optional[str]:
    abi = flags & 0xF000
    return MIPS_ABI.get(abi)


def _kind_of(path: str, elf: Optional[Dict[str, Any]]) -> str:
    if not os.path.exists(path):
        return "missing"
    if _is_link(path):
        return "symlink"
    if os.path.isdir(path):
        return "directory"
    if elf is not None:
        return "elf"
    head = _read(path, 2)
    if head == b"#!":
        return "script"
    return "file"


def _scan_elfs(root: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """优先看启动相关二进制，再有限遍历；返回 ELF 记录与警告。"""
    found: List[Dict[str, Any]] = []
    seen = set()
    warnings: List[str] = []
    priority = ("bin/busybox", "sbin/init", "bin/sh", "init", "linuxrc")

    def add(path: str) -> None:
        rel = os.path.relpath(path, root).replace("\\", "/")
        if rel in seen or len(found) >= 40:
            return
        seen.add(rel)
        elf = parse_elf(path)
        if elf:
            elf["path"] = "/" + rel
            elf["size"] = os.path.getsize(path)
            found.append(elf)

    for rel in priority:
        full = os.path.join(root, rel)
        if os.path.isfile(full) and not _is_link(full):
            add(full)
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        dirnames[:] = [d for d in dirnames
                       if not _is_link(os.path.join(dirpath, d))]
        for fn in sorted(filenames):
            if scanned >= MAX_ELF_SCAN or len(found) >= 40:
                break
            scanned += 1
            full = os.path.join(dirpath, fn)
            if _is_link(full):
                continue
            try:
                if os.path.getsize(full) > MAX_ELF_READ:
                    continue
            except OSError:
                continue
            head = _read(full, 4)
            if head == b"\x7fELF":
                add(full)
        if scanned >= MAX_ELF_SCAN or len(found) >= 40:
            break
    if not found:
        warnings.append("rootfs 中未找到可解析的 ELF；无法自动判定架构")
    return found, warnings


def _choose_arch(elfs: List[Dict[str, Any]], override: str) -> Tuple[Optional[str], int, Optional[str], Optional[str], List[str]]:
    warnings: List[str] = []
    if override and override != "auto":
        if override not in ARCH:
            raise UsageError("不支持的 --arch：%s（可选 auto/%s）"
                             % (override, "/".join(sorted(ARCH))))
        bits = 64 if override.endswith("64") or override in ("aarch64", "x86_64") else 32
        endian = "little" if override.endswith("el") or override in ("arm", "aarch64", "i386", "x86_64") else "big"
        return override, bits, endian, None, warnings
    counts: Dict[str, int] = {}
    first: Dict[str, Dict[str, Any]] = {}
    for elf in elfs:
        arch = elf.get("arch")
        if not arch:
            continue
        counts[arch] = counts.get(arch, 0) + 1
        first.setdefault(arch, elf)
    if not counts:
        return None, 0, None, None, warnings
    arch = max(counts, key=lambda k: (counts[k], k == "mipsel"))
    if len(counts) > 1:
        warnings.append("rootfs 含多种 ELF 架构 %s，按出现最多的 %s 生成计划；"
                        "混合架构需人工确认" % (sorted(counts), arch))
    elf = first[arch]
    abi = _mips_abi(int(elf.get("e_flags") or 0)) if arch.startswith("mips") else None
    return arch, int(elf.get("bits") or 0), elf.get("endian"), abi, warnings


def _find_kernel(rootfs: str, firmware_root: str, explicit: Optional[str]) -> Optional[str]:
    if explicit:
        return os.path.abspath(explicit)
    candidates: List[str] = []
    for name in KERNEL_NAMES:
        candidates.append(os.path.join(rootfs, "boot", name))
        candidates.append(os.path.join(rootfs, name))
        candidates.append(os.path.join(firmware_root, "boot", name))
        candidates.append(os.path.join(firmware_root, name))
    for cand in candidates:
        if os.path.isfile(cand) and not _is_link(cand):
            return os.path.abspath(cand)
    bootdir = os.path.join(rootfs, "boot")
    if os.path.isdir(bootdir):
        for name in sorted(os.listdir(bootdir)):
            if name.startswith("vmlinux-") or name.startswith("Image-"):
                full = os.path.join(bootdir, name)
                if os.path.isfile(full) and not _is_link(full):
                    return os.path.abspath(full)
    return None


def _kernel_format(path: str) -> str:
    head = _read(path, 0x300) or b""
    if head[:4] == b"\x7fELF":
        return "vmlinux"
    if len(head) >= 0x206 and head[0x202:0x206] == b"HdrS":
        return "bzImage"
    if len(head) >= 0x28 and head[0x24:0x28] == b"\x18\x28\x6f\x01":
        return "zImage"
    if len(head) >= 0x40 and head[0x38:0x40] == b"ARM\x64":
        return "Image"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    return "unknown"


def _image_fs(path: str) -> str:
    """读 ext2/3/4 超级块 magic（0xEF53 at 1080）。不挂载、不执行。"""
    try:
        with open(path, "rb") as fh:
            fh.seek(1080)
            raw = fh.read(2)
    except OSError:
        return "unknown"
    if raw == b"\x53\xef":
        return "ext2"
    return "unknown"


def _image_size_mb(total_bytes: int) -> int:
    # 方法论 §5：rootfs 实际字节 + 64–256 MB；小 rootfs 至少 64 MB。
    return max(64, int(total_bytes / (1024 * 1024)) + 128)


def _qemu_lookup(name: str, override: Optional[str]) -> Tuple[str, Optional[str], bool]:
    if override:
        if os.path.isfile(override):
            return name, os.path.abspath(override), True
        found = shutil.which(override)
        return override, found, bool(found)
    found = shutil.which(name)
    return name, found, bool(found)


def _init_probe(rootfs: str, rel: str, elfs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    full = os.path.join(rootfs, rel.lstrip("/"))
    record: Dict[str, Any] = {"path": rel, "kind": "missing",
                              "executable": False, "selected": False}
    if not os.path.exists(full):
        return record
    kind = _kind_of(full, elfs.get(rel))
    record["kind"] = kind
    try:
        record["executable"] = bool(os.stat(full).st_mode & 0o111)
    except OSError:
        pass
    if kind == "symlink":
        try:
            record["link_target"] = os.readlink(full).replace("\\", "/")
        except OSError:
            pass
    if kind == "script":
        head = _read(full, 256) or b""
        first = head.split(b"\n", 1)[0].decode("utf-8", "replace")
        if first.startswith("#!"):
            record["shebang"] = first[2:].strip()
    if kind == "elf":
        elf = elfs.get(rel)
        if elf and elf.get("interp"):
            record["interpreter"] = elf["interp"]
    return record


def _select_init(rootfs: str, elfs: List[Dict[str, Any]], override: Optional[str]) -> Tuple[Optional[str], str, List[Dict[str, Any]], List[str]]:
    by_rel = {e["path"]: e for e in elfs}
    warnings: List[str] = []
    if override:
        rel = override if override.startswith("/") else "/" + override
        rec = _init_probe(rootfs, rel, by_rel)
        if rec["kind"] == "missing":
            raise UsageError("--init 指向的文件不存在：%s" % rel)
        rec["selected"] = True
        return rel, "operator", [rec], warnings
    rows = [_init_probe(rootfs, rel, by_rel) for rel in INIT_CANDIDATES]
    existing = [r for r in rows if r["kind"] != "missing"]
    if not existing:
        return None, "none", rows, ["rootfs 中没有 /sbin/init、/etc/init.d/rcS、"
                                    "/linuxrc、/init 或 /bin/sh"]
    selected = next((r for r in existing if r["executable"]), existing[0])
    if not selected["executable"]:
        warnings.append("init 候选 %s 没有可执行位；镜像构建后仍可能启动失败"
                        % selected["path"])
    selected["selected"] = True
    source = "fallback-shell" if selected["path"] == "/bin/sh" else "firmware"
    if source == "fallback-shell":
        warnings.append("未找到固件 init，计划回落到 /bin/sh；只能证明内核与 rootfs 链路")
    if selected.get("shebang"):
        interp = selected["shebang"].split()[0]
        if interp.startswith("/") and not os.path.exists(
                os.path.join(rootfs, interp.lstrip("/"))):
            warnings.append("init 脚本的解释器不存在于 rootfs：%s" % interp)
    if selected.get("interpreter"):
        interp = selected["interpreter"]
        if interp.startswith("/") and not os.path.exists(
                os.path.join(rootfs, interp.lstrip("/"))):
            warnings.append("init ELF 的动态解释器不存在于 rootfs：%s" % interp)
    return selected["path"], source, rows, warnings


def _fail_code(name: str, message: str, next_action: str) -> Dict[str, str]:
    return {"code": name, "message": message, "next_action": next_action}


def build_plan(args: argparse.Namespace) -> Dict[str, Any]:
    rootfs_path = os.path.abspath(args.rootfs)
    blockers: List[Dict[str, str]] = []
    warnings: List[str] = []
    limitations: List[str] = []

    if not os.path.exists(rootfs_path):
        raise UsageError("--rootfs 不存在：%s" % rootfs_path)
    rootfs_is_dir = os.path.isdir(rootfs_path)
    if not rootfs_is_dir and not os.path.isfile(rootfs_path):
        raise UsageError("--rootfs 既不是目录也不是文件：%s" % rootfs_path)

    firmware_root = os.path.abspath(args.firmware_root) if args.firmware_root \
        else os.path.dirname(rootfs_path)
    if not os.path.isdir(firmware_root):
        raise UsageError("--firmware-root 不是目录：%s" % firmware_root)

    if rootfs_is_dir:
        summary = _dir_summary(rootfs_path, do_hash=not args.no_hash)
        warnings.extend(summary.get("notes") or [])
        if summary["files"] == 0:
            blockers.append(_fail_code(
                "ROOTFS_EMPTY", "rootfs 目录为空", "重新解包固件或改用正确的 rootfs"))
        elfs, elf_warnings = _scan_elfs(rootfs_path)
        warnings.extend(elf_warnings)
        arch, bits, endian, abi, arch_warnings = _choose_arch(elfs, args.arch)
        warnings.extend(arch_warnings)
        selected_init, init_source, init_candidates, init_warnings = _select_init(
            rootfs_path, elfs, args.init)
        warnings.extend(init_warnings)
        interpreter = next((e["interp"] for e in elfs
                            if e.get("path") in ("/bin/busybox", "/sbin/init", "/bin/sh")
                            and e.get("interp")), None)
        libc = []
        for sub in ("lib", "usr/lib", "lib64", "usr/lib64"):
            d = os.path.join(rootfs_path, sub)
            if not os.path.isdir(d):
                continue
            for fn in sorted(os.listdir(d)):
                if fn.startswith(("libc.so", "ld-", "ld-linux", "libuClibc")):
                    libc.append("/" + sub.strip("/") + "/" + fn)
        rootfs_obj: Dict[str, Any] = {
            "path": rootfs_path, "kind": "directory",
            "sha256": summary["sha256"], "files": summary["files"],
            "bytes": summary["bytes"], "arch": arch, "bits": bits or None,
            "endian": endian, "abi": abi, "interpreter": interpreter,
            "libc": libc[:20], "selected_init": selected_init,
            "init_source": init_source, "init_candidates": init_candidates,
            "inittab": os.path.isfile(os.path.join(rootfs_path, "etc/inittab")),
            "evidence": [{"path": e["path"], "size": e.get("size"),
                          "sha256": sha256_file(os.path.join(
                              rootfs_path, e["path"].lstrip("/")))}
                         for e in elfs[:3]],
        }
    else:
        digest = sha256_file(rootfs_path)
        if digest is None:
            raise UsageError("无法读取 rootfs 镜像：%s" % rootfs_path)
        arch = args.arch if args.arch != "auto" else None
        bits = (64 if arch and ("64" in arch or arch == "aarch64") else 32) if arch else None
        endian = None
        if arch:
            endian = "little" if arch.endswith("el") or arch in (
                "arm", "aarch64", "i386", "x86_64") else "big"
        selected_init = args.init
        if selected_init and not selected_init.startswith("/"):
            selected_init = "/" + selected_init
        rootfs_obj = {
            "path": rootfs_path, "kind": "image", "sha256": digest,
            "files": None, "bytes": os.path.getsize(rootfs_path),
            "arch": arch, "bits": bits, "endian": endian, "abi": None,
            "interpreter": None, "libc": [],
            "selected_init": selected_init,
            "init_source": "operator" if selected_init else "none",
            "init_candidates": [],
            "inittab": False, "evidence": [],
        }
        if not arch:
            blockers.append(_fail_code(
                "ARCH_UNKNOWN", "rootfs 是镜像，无法在不挂载的情况下判定架构",
                "补 --arch，或提供可读的 rootfs 目录"))
        if not selected_init:
            warnings.append("rootfs 是镜像且未给 --init；内核将使用自身默认 init")

    if not rootfs_is_dir and _image_fs(rootfs_path) != "ext2":
        warnings.append("rootfs 镜像不是可识别的 ext2/3/4；内核可能无法挂载")

    kernel_path = _find_kernel(rootfs_path if rootfs_is_dir else firmware_root,
                               firmware_root, args.kernel)
    kernel_obj = None
    if kernel_path is None:
        blockers.append(_fail_code(
            "KERNEL_MISSING", "未找到与目标架构匹配的内核",
            "提供 --kernel（vmlinux / zImage / bzImage / Image），没有内核只能改走单二进制仿真"))
    elif not _inside(kernel_path, firmware_root):
        blockers.append(_fail_code(
            "KERNEL_OUTSIDE_MOUNT",
            "内核不在 --firmware-root 内，容器只挂载该目录，QEMU 读不到：%s" % kernel_path,
            "把内核放到 firmware root 下，或用 --firmware-root 指定共同父目录"))
    else:
        kernel_sha = sha256_file(kernel_path)
        kernel_format = _kernel_format(kernel_path)
        kernel_obj = {
            "path": kernel_path, "mount_path": _rel_mount(kernel_path, firmware_root, "/firmware"),
            "sha256": kernel_sha, "size": os.path.getsize(kernel_path),
            "format": kernel_format,
        }
        if kernel_format == "unknown":
            warnings.append("内核格式无法识别；QEMU 可能拒绝 -kernel")
        if kernel_format == "gzip":
            warnings.append("内核是 gzip 压缩流；QEMU 通常需要解压后的 vmlinux/zImage/bzImage/Image")
        if kernel_format == "vmlinux":
            kelf = parse_elf(kernel_path)
            if kelf and rootfs_obj.get("arch") and kelf.get("arch") != rootfs_obj["arch"]:
                blockers.append(_fail_code(
                    "KERNEL_ARCH_MISMATCH",
                    "内核 ELF 架构 %s 与 rootfs 架构 %s 不一致"
                    % (kelf.get("arch"), rootfs_obj["arch"]),
                    "换匹配架构的内核；不能靠改 QEMU 参数解决"))

    image_obj = None
    build_obj = None
    if rootfs_is_dir:
        image_path = os.path.abspath(args.image_out) if args.image_out else \
            os.path.join(firmware_root, os.path.basename(rootfs_path.rstrip(os.sep)) + ".img")
        if not _inside(image_path, firmware_root):
            blockers.append(_fail_code(
                "IMAGE_OUTSIDE_MOUNT", "镜像输出路径不在 --firmware-root 内：%s" % image_path,
                "把 --image-out 放到 firmware root 下，或扩大 --firmware-root"))
        exists = os.path.isfile(image_path)
        fs = _image_fs(image_path) if exists else "unknown"
        image_obj = {
            "path": image_path,
            "mount_path": _rel_mount(image_path, firmware_root, "/firmware"),
            "exists": exists, "sha256": sha256_file(image_path) if exists else None,
            "size": os.path.getsize(image_path) if exists else None,
            "fs": fs,
        }
        need_build = not exists or fs != "ext2"
        if need_build:
            size_mb = _image_size_mb(int(rootfs_obj.get("bytes") or 0))
            build_obj = {
                "required": True, "size_mb": size_mb,
                "commands": [
                    ["truncate", "-s", "%dM" % size_mb, image_path],
                    ["mke2fs", "-q", "-F", "-t", "ext2", "-b", "4096",
                     "-d", rootfs_path, image_path],
                    ["e2fsck", "-fn", image_path],
                ],
                "notes": ["mke2fs -d 不需要 mount/loop；设备节点由 guest devtmpfs 补",
                          "构建命令在宿主机执行；执行前确认 rootfs 来源可信"],
            }
            warnings.append("镜像尚未构建或不是 ext2：先执行 build.commands，再运行 emu_run")
        if exists and fs != "ext2":
            warnings.append("已有镜像不是 ext2/3/4；计划会要求重建")
    else:
        image_obj = {
            "path": rootfs_path,
            "mount_path": _rel_mount(rootfs_path, firmware_root, "/firmware"),
            "exists": True, "sha256": rootfs_obj["sha256"],
            "size": os.path.getsize(rootfs_path), "fs": _image_fs(rootfs_path),
        }
        if image_obj["fs"] != "ext2":
            warnings.append("rootfs 镜像不是 ext2/3/4；内核可能无法挂载")

    arch = rootfs_obj.get("arch")
    if not arch:
        blockers.append(_fail_code(
            "ARCH_UNKNOWN", "无法从 rootfs 判定目标架构",
            "补 --arch（mips/mipsel/arm/aarch64/x86_64 等）或提供含 ELF 的 rootfs"))
        arch = "mipsel"
    conf = ARCH.get(arch)
    if not conf:
        blockers.append(_fail_code(
            "ARCH_UNSUPPORTED", "暂不支持的目标架构：%s" % arch,
            "改用受支持的架构，或扩展 emu_plan.ARCH 与文档矩阵"))
        conf = ARCH["mipsel"]
    machine = args.machine or conf["machine"]
    cpu = args.cpu if args.cpu is not None else conf["cpu"]
    console = args.console or conf["console"]
    root_device = args.root_device or conf["root"]
    disk_bus = args.disk_bus or conf["disk"]
    kernel_format = (kernel_obj or {}).get("format") or conf["kernel"]
    binary, qemu_path, qemu_available = _qemu_lookup(conf["qemu"], args.qemu_bin)
    if not qemu_available:
        msg = "宿主机未找到 %s；容器镜像内也必须有对应 QEMU" % binary
        if args.require_qemu:
            blockers.append(_fail_code("QEMU_MISSING", msg,
                                       "安装 QEMU，或用 --qemu-bin 指向正确的二进制"))
        else:
            warnings.append(msg)

    init_for_cmdline = rootfs_obj.get("selected_init")
    cmdline = "root=%s rw console=%s,115200" % (root_device, console)
    if init_for_cmdline:
        cmdline += " init=%s" % init_for_cmdline
    cmdline += " ignore_loglevel panic=5"

    mem = args.memory
    cpus = str(args.cpus)
    network = {
        "mode": args.network, "hostfwd": list(args.hostfwd or []),
        "guest_ip": "10.0.2.15", "host_forward_reachable": False,
        "notes": ["user-mode 的 hostfwd 只在容器内监听；当前 sandbox_run 不发布端口，"
                  "不能从宿主直接访问 guest 服务"],
    }
    if network["mode"] == "user" and not network["hostfwd"]:
        warnings.append("网络为 user-mode 但没有 hostfwd；guest 可出网，宿主无法访问服务")
    if network["mode"] == "user":
        limitations.append("端口响应必须在容器内验证；本计划不把 hostfwd 开放到宿主")

    disk_args: List[str]
    if disk_bus == "virtio":
        disk_args = ["-drive", "if=none,file=%s,format=raw,id=d0"
                     % image_obj["mount_path"],
                     "-device", "virtio-blk-device,drive=d0"]
    else:
        disk_args = ["-drive", "if=ide,file=%s,format=raw" % image_obj["mount_path"]]

    argv: List[str] = [binary, "-M", machine]
    if cpu:
        argv += ["-cpu", cpu]
    argv += ["-m", mem, "-smp", cpus, "-kernel", kernel_obj["mount_path"]]
    argv += disk_args
    argv += ["-append", cmdline]
    if network["mode"] == "user":
        netdev = "user,id=n0"
        for fwd in network["hostfwd"]:
            netdev += ",hostfwd=" + fwd
        argv += ["-netdev", netdev, "-device", "%s,netdev=n0" % conf["net"]]
    argv += ["-display", "none", "-monitor", "none",
             "-serial", "file:/out/serial.log", "-no-reboot", "-snapshot"]

    qemu_obj = {
        "binary": binary, "path": qemu_path, "available": qemu_available,
        "version": args.qemu_version,
        "machine": machine, "cpu": cpu, "kernel_format": kernel_format,
        "console": console, "root_device": root_device, "disk_bus": disk_bus,
        "argv": argv, "cmdline": cmdline,
        "sandbox_cmd": shlex.join(argv),
        "mounts": {"firmware": "/firmware", "out": "/out"},
    }

    if not args.qemu_version:
        warnings.append("QEMU 版本未知；EmulationResult 的 backend_version 会记为 unverified")

    status = "blocked" if blockers else "ready"
    seed = json.dumps({
        "rootfs": rootfs_obj.get("sha256") or rootfs_obj.get("path"),
        "kernel": (kernel_obj or {}).get("sha256"),
        "image": image_obj.get("path"),
        "arch": arch, "init": rootfs_obj.get("selected_init"),
        "argv": argv,
    }, ensure_ascii=False, sort_keys=True).encode("utf-8")
    plan_id = "PLAN-" + hashlib.sha256(seed).hexdigest()[:12]
    if status == "blocked":
        limitations.append("计划存在阻断项；未生成可直接执行的完整启动条件")

    plan = {
        "schema": SCHEMA,
        "tool": TOOL,
        "version": VERSION,
        "plan_id": plan_id,
        "run_id": args.run_id,
        "intent_id": args.intent_id,
        "firmware_sha256": args.firmware_sha256,
        "status": status,
        "blockers": blockers,
        "warnings": warnings,
        "firmware_root": firmware_root,
        "rootfs": rootfs_obj,
        "kernel": kernel_obj,
        "image": image_obj,
        "build": build_obj,
        "qemu": qemu_obj,
        "network": network,
        "budget": {"timeout_s": args.timeout, "memory": mem,
                   "cpus": cpus, "attempts": 1},
        "limitations": limitations,
    }
    return plan


def render_md(plan: Dict[str, Any]) -> str:
    st = plan.get("status")
    icon = "✅" if st == "ready" else "⛔"
    lines = ["# 整机仿真启动计划（%s）" % plan.get("plan_id"),
             "",
             "%s **%s**" % (icon, st),
             "",
             "## 目标",
             "",
             "| 项 | 值 |",
             "|---|---|"]
    rootfs = plan.get("rootfs") or {}
    kernel = plan.get("kernel") or {}
    image = plan.get("image") or {}
    qemu = plan.get("qemu") or {}
    rows = [
        ("rootfs", rootfs.get("path")),
        ("类型", rootfs.get("kind")),
        ("架构", "%s / %s-bit / %s" % (rootfs.get("arch"), rootfs.get("bits"), rootfs.get("endian"))),
        ("init", rootfs.get("selected_init") or "（内核默认）"),
        ("kernel", kernel.get("path") or "（缺失）"),
        ("kernel format", kernel.get("format")),
        ("image", image.get("path") or "（未指定）"),
        ("QEMU", qemu.get("binary")),
        ("machine / cpu", "%s / %s" % (qemu.get("machine"), qemu.get("cpu") or "默认")),
    ]
    for key, val in rows:
        lines.append("| %s | %s |" % (key, val))
    if plan.get("blockers"):
        lines += ["", "## 阻断项（必须先解决）", ""]
        for b in plan["blockers"]:
            lines.append("- **%s**：%s；下一步：%s"
                         % (b.get("code"), b.get("message"), b.get("next_action")))
    if plan.get("warnings"):
        lines += ["", "## 警告（不阻断，但会影响解释）", ""]
        lines += ["- %s" % w for w in plan["warnings"]]
    build = plan.get("build") or {}
    if build.get("required"):
        lines += ["", "## 构建镜像", "", FENCE + "bash"]
        lines += [shlex.join(cmd) for cmd in build.get("commands") or []]
        lines += [FENCE, "",
                  "镜像大小：%s MB；构建在宿主机完成，执行仍由 sandbox_run 负责。"
                  % build.get("size_mb")]
    lines += ["", "## QEMU 命令（容器内）", "", FENCE + "bash",
              qemu.get("sandbox_cmd") or "", FENCE, "",
              "内核参数：", "", FENCE + "text", qemu.get("cmdline") or "", FENCE]
    if plan.get("limitations"):
        lines += ["", "## 适用范围与限制", ""]
        lines += ["- %s" % x for x in plan["limitations"]]
    lines += ["", "---", "",
              "本计划只证明「准备用什么参数启动」，不证明启动一定成功；"
              "端口开放也不等于漏洞。执行后以 EmulationResult 的 observations 为准。"]
    return "\n".join(lines) + "\n"


def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("必须是整数")
    if n <= 0:
        raise argparse.ArgumentTypeError("必须大于 0")
    return n


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="只读探测 rootfs 并生成 QEMU 整机启动计划（不执行）")
    ap.add_argument("--rootfs", required=True,
                    help="rootfs 目录，或已构建的 ext2 镜像")
    ap.add_argument("--kernel",
                    help="内核文件；缺省在 rootfs/boot 与 firmware root 中查找")
    ap.add_argument("--firmware-root",
                    help="容器只读挂载的根目录（默认 rootfs 的父目录）；内核与镜像必须在其下")
    ap.add_argument("--image-out",
                    help="rootfs 目录要构建的 ext2 镜像路径（默认 <firmware-root>/<name>.img）")
    ap.add_argument("--arch", default="auto",
                    help="目标架构：auto 或 %s" % "/".join(sorted(ARCH)))
    ap.add_argument("--init", help="强制指定 init 路径（如 /sbin/init 或 /bin/sh）")
    ap.add_argument("--machine", help="覆盖 QEMU machine")
    ap.add_argument("--cpu", help="覆盖 QEMU -cpu（空字符串表示不传）")
    ap.add_argument("--console", help="覆盖 console，如 ttyS0 / ttyAMA0")
    ap.add_argument("--root-device", help="覆盖 root=，如 /dev/sda /dev/vda")
    ap.add_argument("--disk-bus", choices=("ide", "virtio"), help="覆盖磁盘总线")
    ap.add_argument("--qemu-bin", help="QEMU 二进制名或路径（用于可用性检查）")
    ap.add_argument("--qemu-version", help="已知 QEMU 版本；不执行 QEMU 探测")
    ap.add_argument("--require-qemu", action="store_true",
                    help="宿主机找不到 QEMU 时记为阻断项（默认只警告）")
    ap.add_argument("--network", choices=("none", "user"), default="none",
                    help="QEMU 网络模型；默认 none")
    ap.add_argument("--hostfwd", action="append", default=[],
                    help="user-mode 端口转发，如 tcp:127.0.0.1:8080-:80（可重复）")
    ap.add_argument("--memory", default="512m", help="guest 内存（默认 512m）")
    ap.add_argument("--cpus", default="1", help="vCPU 数（默认 1）")
    ap.add_argument("--timeout", type=_positive_int, default=120,
                    help="单次观察窗口秒数（默认 120）")
    ap.add_argument("--run-id", help="写入计划的 run_id（可选）")
    ap.add_argument("--intent-id", help="写入计划的 intent_id（可选）")
    ap.add_argument("--firmware-sha256",
                    help="固件 sha256（64 位十六进制；可选，执行时仍要复核）")
    ap.add_argument("--no-hash", action="store_true",
                    help="不计算 rootfs 清单哈希（大 rootfs 可加速，但会失去指纹）")
    ap.add_argument("--json", dest="json_out", help="输出计划 JSON 路径")
    ap.add_argument("--md", dest="md_out", help="输出中文 Markdown 路径")
    ap.add_argument("--quiet", action="store_true", help="不打印人类可读摘要")
    return ap


def validate_args(args: argparse.Namespace) -> None:
    if args.firmware_sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", args.firmware_sha256):
        raise UsageError("--firmware-sha256 必须是 64 位十六进制")
    if args.firmware_sha256:
        args.firmware_sha256 = args.firmware_sha256.lower()
    if args.arch != "auto" and args.arch not in ARCH:
        raise UsageError("不支持的 --arch：%s" % args.arch)
    if args.timeout <= 0:
        raise UsageError("--timeout 必须大于 0")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?[bkmgBKMG]?", args.memory or ""):
        raise UsageError("--memory 格式不合法（如 512m / 1g）")
    try:
        if float(args.cpus) <= 0:
            raise ValueError
    except ValueError:
        raise UsageError("--cpus 必须是正数")


def main(argv=None) -> int:
    _force_utf8_io()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        validate_args(args)
        plan = build_plan(args)
        if args.json_out:
            _write_json(args.json_out, plan)
        if args.md_out:
            _write_text(args.md_out, render_md(plan))
    except UsageError as exc:
        _say("[error] %s" % exc, sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        _say("[error] 读取/写入失败：%s" % exc, sys.stderr)
        return EXIT_USAGE

    if not args.quiet:
        st = plan["status"]
        _say("[%s] %s  arch=%s init=%s" % (
            st, plan["plan_id"], (plan.get("rootfs") or {}).get("arch"),
            (plan.get("rootfs") or {}).get("selected_init")))
        for b in plan.get("blockers") or []:
            _say("  BLOCK %s: %s" % (b.get("code"), b.get("message")), sys.stderr)
        for w in plan.get("warnings") or []:
            _say("  WARN  %s" % w, sys.stderr)
        if args.json_out:
            _say("[ok] JSON → %s" % args.json_out)
        if args.md_out:
            _say("[ok] Markdown → %s" % args.md_out)
    return EXIT_OK if plan["status"] == "ready" else EXIT_BLOCKED


if __name__ == "__main__":
    raise SystemExit(main())
