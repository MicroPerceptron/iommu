#!/usr/bin/env python3
"""
pci_ids.py — generates `src/platform/res/bdf.rs` from the upstream
`pci.ids` database maintained at https://pci-ids.ucw.cz/.

The upstream DB is the *observed-in-the-wild* source of truth:
vendor and device IDs are added when hardware shows up, without
waiting for a corresponding in-tree driver. That's a better match
for kraph's discovery-first kernel model than the Linux kernel's
`include/linux/pci_ids.h`, which only names devices that a driver
source file already references.

Usage:
    python3 tools/pci_ids.py                    # use cached pci.ids, fetch if missing
    python3 tools/pci_ids.py --refresh          # force re-fetch latest
    python3 tools/pci_ids.py --source PATH      # explicit local file (no fetch)
    python3 tools/pci_ids.py --output PATH      # write to PATH instead of stdout
    python3 tools/pci_ids.py --overlay PATH     # merge in extra IDs in pci.ids format

Outputs the same open-enum shape the old C-header-parsing generator
produced, so downstream Rust code is unchanged:

  • `pub enum Vendor`             — one variant per vendor ID
  • `pub enum <Vendor>Device`     — per-vendor device enums
  • `pub enum PciDevice`          — unified vendor+device wrapper
  • `pub enum Class`              — PCI base class byte
  • `pub enum <Class>Subclass`    — per-class subclass enums
  • `pub enum Subclass`           — unified class+subclass wrapper
  • `pub enum <Class><Subclass>ProgIf`  — per-subclass progif enums
  • `pub enum ProgIf`             — unified subclass+progif wrapper

Every enum carries an `Unknown(raw)` fallback so decode is total.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

UPSTREAM_URL = "https://pci-ids.ucw.cz/v2.2/pci.ids"
DEFAULT_CACHE = Path(__file__).resolve().parent / ".pci_ids.cache"


# ── Name sanitization ────────────────────────────────────────────────────────


# Corporate suffixes to strip from vendor names.
_CORP_SUFFIX_RE = re.compile(
    r"[,\s]*(?:"
    r"Corporation|Corp\.?|Incorporated|Inc\.?|Ltd\.?|Limited|LLC\.?|"
    r"L\.P\.|L\.L\.C\.|LP|GmbH|AG|S\.A\.?|SA|SAS|NV|BV|Pty\.?|"
    r"Co\.?|Company|Technologies|Technology|Tech|Semiconductor"
    r")\s*$",
    re.IGNORECASE,
)


def _pascal_tokens(tokens: list[str], max_tokens: int | None = None) -> str:
    """PascalCase a list of tokens.  Runs of digits stay as-is; letter
    groups get their leading character uppercased."""
    if max_tokens is not None:
        tokens = tokens[:max_tokens]
    parts: list[str] = []
    for t in tokens:
        if not t:
            continue
        if t[0].isdigit():
            parts.append(t.lower())
        else:
            parts.append(t[:1].upper() + t[1:].lower())
    result = "".join(parts)
    return result


def sanitize_vendor_name(raw: str) -> str:
    """Turn a pci.ids vendor description into a compact PascalCase
    identifier.

    Heuristics (in priority order):
      1. If a trailing `[ALIAS]` bracketed tag exists, use its contents
         — vendors commonly use that for short forms (e.g. AMD, AMI).
      2. Strip corporate suffixes ("Corporation", ", Inc.", etc.).
      3. Pascal-case the remaining tokens.

    Falls back to `"Unknown"` for empty strings (shouldn't happen on
    real pci.ids entries but keeps the pipeline total).
    """
    s = raw.strip()

    m = re.search(r"\[([^\]]+)\]\s*$", s)
    if m:
        s = m.group(1).strip()
    else:
        s = _CORP_SUFFIX_RE.sub("", s)

    tokens = re.split(r"[^A-Za-z0-9]+", s)
    tokens = [t for t in tokens if t]
    pascal = _pascal_tokens(tokens)
    if not pascal:
        return "Unknown"
    if pascal[0].isdigit():
        pascal = "V" + pascal
    return pascal


def sanitize_device_name(raw: str, max_tokens: int = 4) -> str:
    """Turn a pci.ids device description into a compact PascalCase
    identifier.

    Heuristics:
      1. If the description contains a `[CODE]` bracketed tag, use just
         the tag (model codes like "AD102" or "GeForce RTX 4090").
      2. Otherwise keep the first `max_tokens` tokens.
      3. Pascal-case; prefix a digit-leading result with `D`.
    """
    s = raw.strip()

    m = re.search(r"\[([^\]]+)\]", s)
    if m:
        s = m.group(1).strip()

    # Stop at punctuation that marks a parenthetical clause.
    s = re.sub(r"\s*\(.*?\)\s*$", "", s)

    tokens = re.split(r"[^A-Za-z0-9]+", s)
    tokens = [t for t in tokens if t]
    pascal = _pascal_tokens(tokens, max_tokens)
    if not pascal:
        return "Unknown"
    if pascal[0].isdigit():
        pascal = "D" + pascal
    return pascal


def sanitize_class_name(raw: str) -> str:
    """Class/subclass names are typically short English phrases —
    pascal the whole thing with no token cap."""
    s = raw.strip()
    tokens = re.split(r"[^A-Za-z0-9]+", s)
    tokens = [t for t in tokens if t]
    pascal = _pascal_tokens(tokens)
    if not pascal:
        return "Unknown"
    if pascal[0].isdigit():
        pascal = "C" + pascal
    return pascal


# ── Fetch + parse pci.ids ────────────────────────────────────────────────────


def fetch_pci_ids(cache: Path, refresh: bool) -> str:
    if cache.exists() and not refresh:
        return cache.read_text(encoding="utf-8", errors="replace")
    print(f"[pci_ids] fetching {UPSTREAM_URL}", file=sys.stderr)
    req = urllib.request.Request(UPSTREAM_URL, headers={"User-Agent": "kraph-pci-ids-generator"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read().decode("utf-8", errors="replace")
    cache.write_text(data, encoding="utf-8")
    return data


class PciIds:
    """Parsed pci.ids tree.

    Attributes:
      vendors:    {vid (u16): pretty name}
      devices:    {vid: {pid (u16): pretty name}}
      classes:    {cid (u8): pretty name}
      subclasses: {cid: {scid (u8): pretty name}}
      progifs:    {(cid, scid): {piid (u8): pretty name}}
    """

    def __init__(self) -> None:
        self.vendors: dict[int, str] = {}
        self.devices: dict[int, dict[int, str]] = defaultdict(dict)
        self.classes: dict[int, str] = {}
        self.subclasses: dict[int, dict[int, str]] = defaultdict(dict)
        self.progifs: dict[tuple[int, int], dict[int, str]] = defaultdict(dict)

    def merge(self, other: "PciIds") -> None:
        """Merge `other` into `self` — later entries win, so the
        overlay file's values override upstream where both define the
        same ID."""
        self.vendors.update(other.vendors)
        for vid, devs in other.devices.items():
            self.devices[vid].update(devs)
        self.classes.update(other.classes)
        for cid, subs in other.subclasses.items():
            self.subclasses[cid].update(subs)
        for key, pis in other.progifs.items():
            self.progifs[key].update(pis)


def parse_pci_ids(text: str) -> PciIds:
    db = PciIds()

    current_vendor: int | None = None
    current_device: int | None = None
    current_class: int | None = None
    current_subclass: int | None = None
    # Tracks whether the current indentation context is under a vendor
    # (so tab-2 means subsystem, ignored) or under a class (so tab-2
    # means progif, stored).
    mode: str | None = None  # "vendor" | "class" | None

    for raw_line in text.splitlines():
        if not raw_line or raw_line.lstrip().startswith("#"):
            continue
        # Count leading tabs for indent.
        stripped = raw_line.lstrip("\t")
        depth = len(raw_line) - len(stripped)

        if depth == 0:
            if stripped.startswith("C "):
                # `C XX  Name`
                m = re.match(r"C\s+([0-9A-Fa-f]{2})\s+(.+)$", stripped)
                if not m:
                    continue
                cid = int(m.group(1), 16)
                db.classes[cid] = m.group(2).strip()
                current_class = cid
                current_subclass = None
                mode = "class"
                current_vendor = None
                current_device = None
            else:
                # `VVVV  Name`
                m = re.match(r"([0-9A-Fa-f]{4})\s+(.+)$", stripped)
                if not m:
                    continue
                vid = int(m.group(1), 16)
                db.vendors[vid] = m.group(2).strip()
                current_vendor = vid
                current_device = None
                mode = "vendor"
                current_class = None
                current_subclass = None
        elif depth == 1:
            if mode == "vendor" and current_vendor is not None:
                # `\tPID  Name`
                m = re.match(r"([0-9A-Fa-f]{4})\s+(.+)$", stripped)
                if not m:
                    continue
                pid = int(m.group(1), 16)
                db.devices[current_vendor][pid] = m.group(2).strip()
                current_device = pid
            elif mode == "class" and current_class is not None:
                # `\tSCID  Name`
                m = re.match(r"([0-9A-Fa-f]{2})\s+(.+)$", stripped)
                if not m:
                    continue
                scid = int(m.group(1), 16)
                db.subclasses[current_class][scid] = m.group(2).strip()
                current_subclass = scid
        elif depth == 2:
            if mode == "vendor":
                # Subsystem entry under a vendor/device — we don't
                # track subsystems, skip.
                continue
            if (
                mode == "class"
                and current_class is not None
                and current_subclass is not None
            ):
                # `\t\tPIID  Name`
                m = re.match(r"([0-9A-Fa-f]{2})\s+(.+)$", stripped)
                if not m:
                    continue
                piid = int(m.group(1), 16)
                db.progifs[(current_class, current_subclass)][piid] = m.group(2).strip()

    return db


# ── Dedup / collision helpers (shared with old generator) ────────────────────


def dedup_by_value(
    items: list[tuple[str, int]],
) -> tuple[list[tuple[str, int]], dict[int, list[str]]]:
    """Split `items` into canonical (first-seen) and aliases for
    duplicate IDs. Matches the old generator's dedup behaviour."""
    seen: dict[int, str] = {}
    canon: list[tuple[str, int]] = []
    aliases: dict[int, list[str]] = defaultdict(list)
    for name, val in items:
        if val not in seen:
            seen[val] = name
            canon.append((name, val))
        else:
            aliases[val].append(name)
    return canon, aliases


def resolve_name_collisions(
    variants: list[tuple[str, int]],
    repr_ty: str,
) -> list[tuple[str, int]]:
    digits = 2 if repr_ty == "u8" else 4
    name_counts: dict[str, int] = defaultdict(int)
    for pname, _ in variants:
        name_counts[pname] += 1
    colliding = {n for n, c in name_counts.items() if c > 1}
    if not colliding:
        return variants
    return [
        (f"{pname}X{val:0{digits}x}" if pname in colliding else pname, val)
        for pname, val in variants
    ]


def dedup_name_collisions_across_enums(
    variants: list[tuple[str, int]],
    reserved: set[str],
    repr_ty: str,
) -> list[tuple[str, int]]:
    """Ensure none of `variants` collide with any name in `reserved`."""
    digits = 2 if repr_ty == "u8" else 4
    out: list[tuple[str, int]] = []
    for pname, val in variants:
        safe_name = pname
        if pname in reserved:
            safe_name = f"{pname}X{val:0{digits}x}"
        out.append((safe_name, val))
    return out


# ── Emitter (preserved from the old generator, shape-compatible) ─────────────

HEADER = """\
// pci_ids.rs — AUTO-GENERATED from https://pci-ids.ucw.cz/ upstream pci.ids.
// Do NOT edit by hand.  Re-run tools/pci_ids.py to regenerate.

#![allow(
    non_camel_case_types,
    clippy::upper_case_acronyms,
    clippy::unreadable_literal,
    dead_code,
)]

use core::fmt;
"""


def emit_open_enum(
    name: str,
    repr_ty: str,
    variants: list[tuple[str, int]],
    const_aliases: list[tuple[str, str]],
    *,
    doc: str = "",
) -> str:
    digits = 2 if repr_ty == "u8" else 4

    def h(v: int) -> str:
        return f"0x{v:0{digits}x}"

    variants = [
        (f"UnknownX{val:0{digits}x}" if vname == "Unknown" else vname, val)
        for vname, val in variants
    ]

    max_val = 0xFF if repr_ty == "u8" else 0xFFFF
    used_vals = {v for _, v in variants}
    unknown_disc = max_val
    while unknown_disc in used_vals:
        unknown_disc -= 1

    lines: list[str] = []
    if doc:
        lines.append(f"/// {doc}")
    lines.append(f"#[repr({repr_ty})]")
    lines.append("#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]")
    lines.append(f"pub enum {name} {{")
    for vname, val in variants:
        lines.append(f"    {vname} = {h(val)},")
    lines.append("    /// Unrecognized raw identifier — carries the discovered byte(s).")
    lines.append(f"    Unknown({repr_ty}) = {h(unknown_disc)},")
    lines.append("}")
    lines.append("")

    lines.append(f"impl {name} {{")
    for alias, canon in const_aliases:
        lines.append(f"    /// Alias — same value as [`{name}::{canon}`].")
        lines.append("    #[allow(non_upper_case_globals)]")
        lines.append(f"    pub const {alias}: Self = Self::{canon};")
    if const_aliases:
        lines.append("")
    lines.append("    /// Raw identifier carried by this variant.")
    lines.append("    #[inline]")
    lines.append(f"    pub const fn id(self) -> {repr_ty} {{")
    lines.append("        match self {")
    for vname, val in variants:
        lines.append(f"            Self::{vname} => {h(val)},")
    lines.append("            Self::Unknown(v) => v,")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    lines.append(f"impl core::convert::From<{repr_ty}> for {name} {{")
    lines.append(f"    fn from(v: {repr_ty}) -> Self {{")
    lines.append("        match v {")
    for vname, val in variants:
        lines.append(f"            {h(val)} => Self::{vname},")
    lines.append("            other => Self::Unknown(other),")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    lines.append(f"impl fmt::Display for {name} {{")
    lines.append("    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {")
    lines.append("        match self {")
    for vname, _ in variants:
        display_name = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", vname)
        display_name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", display_name)
        lines.append(f'            Self::{vname} => f.write_str("{display_name}"),')
    unknown_fmt = f"Unknown({{v:#0{digits + 2}x}})"
    lines.append(f'            Self::Unknown(v) => write!(f, "{unknown_fmt}"),')
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def emit_pci_device_enum(
    vendor_variants: list[tuple[str, int]],
    device_enum_names: list[str],
) -> str:
    lines: list[str] = []

    vendor_to_device_enum: dict[str, str] = {}
    for ename in device_enum_names:
        vendor_to_device_enum[ename.removesuffix("Device")] = ename

    lines.append("/// Unified PCI device identity, resolved from `(Vendor, device_id)`.")
    lines.append("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
    lines.append("pub enum PciDevice {")
    for vp, _ in vendor_variants:
        if vp in vendor_to_device_enum:
            lines.append(f"    {vp}({vendor_to_device_enum[vp]}),")
    lines.append("    /// Vendor-unknown device: carries the raw `(vendor_id, device_id)` pair.")
    lines.append("    Unknown(u16, u16),")
    lines.append("}")
    lines.append("")

    lines.append("impl PciDevice {")
    lines.append("    /// Raw `device_id` byte pair associated with this value.")
    lines.append("    #[inline]")
    lines.append("    pub const fn id(self) -> u16 {")
    lines.append("        match self {")
    for vp, _ in vendor_variants:
        if vp in vendor_to_device_enum:
            lines.append(f"            Self::{vp}(d) => d.id(),")
    lines.append("            Self::Unknown(_, d) => d,")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    lines.append("impl core::convert::From<(Vendor, u16)> for PciDevice {")
    lines.append("    fn from((vendor, device_id): (Vendor, u16)) -> Self {")
    lines.append("        match vendor {")
    for vp, _ in vendor_variants:
        if vp in vendor_to_device_enum:
            dname = vendor_to_device_enum[vp]
            lines.append(
                f"            Vendor::{vp} => Self::{vp}({dname}::from(device_id)),"
            )
    lines.append("            Vendor::Unknown(v) => Self::Unknown(v, device_id),")
    lines.append("            other => Self::Unknown(other.id(), device_id),")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    lines.append("impl fmt::Display for PciDevice {")
    lines.append("    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {")
    lines.append("        match self {")
    for vp, _ in vendor_variants:
        if vp in vendor_to_device_enum:
            lines.append(f'            Self::{vp}(d) => write!(f, "{vp} {{d}}"),')
    lines.append(
        '            Self::Unknown(v, d) => write!(f, "Unknown({v:#06x}:{d:#06x})"),'
    )
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def emit_subclass_enum(
    class_variants: list[tuple[str, int]], sub_enum_names: list[str]
) -> str:
    lines: list[str] = []

    class_to_sub: dict[str, str] = {}
    for ename in sub_enum_names:
        class_to_sub[ename.removesuffix("Subclass")] = ename

    lines.append("/// Unified PCI subclass, resolved from `(Class, subclass_id)`.")
    lines.append("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
    lines.append("pub enum Subclass {")
    for cp, _ in class_variants:
        if cp in class_to_sub:
            lines.append(f"    {cp}({class_to_sub[cp]}),")
    lines.append("    /// Class-unknown subclass: carries the raw `(class_id, subclass_id)` pair.")
    lines.append("    Unknown(u8, u8),")
    lines.append("}")
    lines.append("")

    lines.append("impl Subclass {")
    lines.append("    /// Raw subclass byte associated with this value.")
    lines.append("    #[inline]")
    lines.append("    pub const fn id(self) -> u8 {")
    lines.append("        match self {")
    for cp, _ in class_variants:
        if cp in class_to_sub:
            lines.append(f"            Self::{cp}(s) => s.id(),")
    lines.append("            Self::Unknown(_, s) => s,")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    lines.append("impl core::convert::From<(Class, u8)> for Subclass {")
    lines.append("    fn from((class, subclass_id): (Class, u8)) -> Self {")
    lines.append("        match class {")
    for cp, _ in class_variants:
        if cp in class_to_sub:
            sname = class_to_sub[cp]
            lines.append(
                f"            Class::{cp} => Self::{cp}({sname}::from(subclass_id)),"
            )
    lines.append("            other => Self::Unknown(other.id(), subclass_id),")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    lines.append("impl fmt::Display for Subclass {")
    lines.append("    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {")
    lines.append("        match self {")
    for cp, _ in class_variants:
        if cp in class_to_sub:
            lines.append(f'            Self::{cp}(s) => write!(f, "{cp}::{{s}}"),')
    lines.append(
        '            Self::Unknown(c, s) => write!(f, "Unknown({c:#04x}:{s:#04x})"),',
    )
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def emit_progif_enum(progif_info: list[tuple[str, str, str]]) -> str:
    lines: list[str] = []

    lines.append("/// Unified PCI programming interface, resolved from `(Subclass, prog_if_id)`.")
    lines.append("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
    lines.append("pub enum ProgIf {")
    for class_p, sub_p, ename in progif_info:
        variant = f"{class_p}{sub_p}"
        lines.append(f"    {variant}({ename}),")
    lines.append("    /// Unrecognized or no programming interface defined.")
    lines.append("    Unknown(u8),")
    lines.append("}")
    lines.append("")

    lines.append("impl ProgIf {")
    lines.append("    /// Resolve the programming interface from a subclass and raw prog-if byte.")
    lines.append("    pub fn from_subclass(subclass: &Subclass, prog_if_id: u8) -> Self {")
    lines.append("        match subclass {")
    for class_p, sub_p, ename in progif_info:
        variant = f"{class_p}{sub_p}"
        lines.append(
            f"            Subclass::{class_p}({class_p}Subclass::{sub_p}) => "
            f"Self::{variant}({ename}::from(prog_if_id)),"
        )
    lines.append("            _ => Self::Unknown(prog_if_id),")
    lines.append("        }")
    lines.append("    }")
    lines.append("")
    lines.append("    /// Raw programming-interface byte associated with this value.")
    lines.append("    #[inline]")
    lines.append("    pub const fn id(self) -> u8 {")
    lines.append("        match self {")
    for class_p, sub_p, _ in progif_info:
        variant = f"{class_p}{sub_p}"
        lines.append(f"            Self::{variant}(p) => p.id(),")
    lines.append("            Self::Unknown(v) => v,")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    lines.append("impl fmt::Display for ProgIf {")
    lines.append("    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {")
    lines.append("        match self {")
    for class_p, sub_p, _ in progif_info:
        variant = f"{class_p}{sub_p}"
        lines.append(f'            Self::{variant}(p) => write!(f, "{{p}}"),')
    lines.append('            Self::Unknown(v) => write!(f, "Unknown({v:#04x})"),')
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


# ── Orchestration ────────────────────────────────────────────────────────────


def build_variants_from_db(db: PciIds) -> str:
    """Run the full emit pipeline against a parsed database.

    Returns the full `bdf.rs` source text.
    """
    out = HEADER + "\n"

    # ── Vendor enum ──────────────────────────────────────────────────────────
    vendor_items: list[tuple[str, int]] = []
    for vid in sorted(db.vendors):
        pascal = sanitize_vendor_name(db.vendors[vid])
        vendor_items.append((pascal, vid))

    v_canon, v_aliases = dedup_by_value(vendor_items)
    v_canon = resolve_name_collisions(v_canon, "u16")
    v_val_to_pascal = {val: p for p, val in v_canon}

    v_const_aliases: list[tuple[str, str]] = []
    for val, alias_shorts in v_aliases.items():
        canon_pascal = v_val_to_pascal[val]
        for alias_p in alias_shorts:
            if alias_p != canon_pascal:
                v_const_aliases.append((alias_p, canon_pascal))

    out += emit_open_enum(
        "Vendor",
        "u16",
        v_canon,
        v_const_aliases,
        doc="PCI Vendor IDs sourced from the upstream pci.ids database.",
    )

    # ── Per-vendor Device enums ──────────────────────────────────────────────
    device_enum_names: list[str] = []
    # Emit in vendor-pascal alphabetical order for stability.
    for vid, canon_pascal in sorted(v_val_to_pascal.items(), key=lambda kv: kv[1]):
        devices = db.devices.get(vid, {})
        if not devices:
            continue
        enum_name = canon_pascal + "Device"
        device_enum_names.append(enum_name)

        d_items: list[tuple[str, int]] = []
        for pid in sorted(devices):
            d_items.append((sanitize_device_name(devices[pid]), pid))

        d_canon, d_aliases = dedup_by_value(d_items)
        d_canon = resolve_name_collisions(d_canon, "u16")
        d_val_to_pascal = {v: p for p, v in d_canon}

        d_const_aliases: list[tuple[str, str]] = []
        for val, alist in d_aliases.items():
            cp = d_val_to_pascal[val]
            for alias_p in alist:
                if alias_p != cp:
                    d_const_aliases.append((alias_p, cp))

        out += emit_open_enum(
            enum_name,
            "u16",
            d_canon,
            d_const_aliases,
            doc=f"Device IDs for [`Vendor::{canon_pascal}`].",
        )

    # ── PciDevice unified enum ───────────────────────────────────────────────
    out += emit_pci_device_enum(v_canon, device_enum_names)

    # ── Class enum ───────────────────────────────────────────────────────────
    class_items: list[tuple[str, int]] = []
    for cid in sorted(db.classes):
        class_items.append((sanitize_class_name(db.classes[cid]), cid))
    # Ensure "Others" class 0xFF exists even if pci.ids omits it —
    # downstream assume-exists code depends on it.
    if not any(v == 0xFF for _, v in class_items):
        class_items.append(("Others", 0xFF))
    c_canon, c_aliases = dedup_by_value(class_items)
    c_canon = resolve_name_collisions(c_canon, "u8")
    c_val_to_pascal = {v: p for p, v in c_canon}
    c_const_aliases: list[tuple[str, str]] = []
    for val, alist in c_aliases.items():
        cp = c_val_to_pascal[val]
        for alias_p in alist:
            if alias_p != cp:
                c_const_aliases.append((alias_p, cp))
    out += emit_open_enum(
        "Class",
        "u8",
        c_canon,
        c_const_aliases,
        doc="PCI base class byte sourced from the upstream pci.ids database.",
    )

    # ── Per-class Subclass enums ─────────────────────────────────────────────
    sub_enum_names: list[str] = []
    subclass_pascal_by_key: dict[tuple[int, int], str] = {}
    for cid in sorted(db.subclasses):
        class_pascal = c_val_to_pascal.get(cid)
        if class_pascal is None:
            continue
        subs = db.subclasses[cid]
        if not subs:
            continue
        enum_name = f"{class_pascal}Subclass"
        sub_enum_names.append(enum_name)

        s_items: list[tuple[str, int]] = []
        for scid in sorted(subs):
            s_items.append((sanitize_class_name(subs[scid]), scid))
        s_canon, s_aliases = dedup_by_value(s_items)
        s_canon = resolve_name_collisions(s_canon, "u8")
        s_val_to_pascal = {v: p for p, v in s_canon}
        s_const_aliases: list[tuple[str, str]] = []
        for val, alist in s_aliases.items():
            cp = s_val_to_pascal[val]
            for alias_p in alist:
                if alias_p != cp:
                    s_const_aliases.append((alias_p, cp))

        for scid, scp in s_val_to_pascal.items():
            subclass_pascal_by_key[(cid, scid)] = scp

        out += emit_open_enum(
            enum_name,
            "u8",
            s_canon,
            s_const_aliases,
            doc=f"Subclass codes for [`Class::{class_pascal}`].",
        )

    # ── Subclass unified enum ────────────────────────────────────────────────
    out += emit_subclass_enum(c_canon, sub_enum_names)

    # ── Per-subclass ProgIf enums ────────────────────────────────────────────
    progif_info: list[tuple[str, str, str]] = []
    for (cid, scid) in sorted(db.progifs):
        class_pascal = c_val_to_pascal.get(cid)
        sub_pascal = subclass_pascal_by_key.get((cid, scid))
        if class_pascal is None or sub_pascal is None:
            continue
        pis = db.progifs[(cid, scid)]
        if not pis:
            continue
        enum_name = f"{class_pascal}{sub_pascal}ProgIf"

        p_items: list[tuple[str, int]] = []
        for piid in sorted(pis):
            p_items.append((sanitize_class_name(pis[piid]), piid))
        p_canon, p_aliases = dedup_by_value(p_items)
        p_canon = resolve_name_collisions(p_canon, "u8")
        p_val_to_pascal = {v: p for p, v in p_canon}
        p_const_aliases: list[tuple[str, str]] = []
        for val, alist in p_aliases.items():
            cp = p_val_to_pascal[val]
            for alias_p in alist:
                if alias_p != cp:
                    p_const_aliases.append((alias_p, cp))

        out += emit_open_enum(
            enum_name,
            "u8",
            p_canon,
            p_const_aliases,
            doc=f"Programming interface for [`{class_pascal}Subclass::{sub_pascal}`].",
        )
        progif_info.append((class_pascal, sub_pascal, enum_name))

    # ── ProgIf unified enum ──────────────────────────────────────────────────
    out += emit_progif_enum(progif_info)

    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--source",
        type=Path,
        help="Local pci.ids file to use instead of fetching upstream.",
    )
    ap.add_argument(
        "--overlay",
        type=Path,
        help="Extra pci.ids-format file whose entries overlay upstream (later-wins).",
    )
    ap.add_argument(
        "--cache",
        type=Path,
        default=DEFAULT_CACHE,
        help=f"Cache path for the fetched pci.ids file (default: {DEFAULT_CACHE.relative_to(Path.cwd()) if DEFAULT_CACHE.is_relative_to(Path.cwd()) else DEFAULT_CACHE}).",
    )
    ap.add_argument(
        "--refresh",
        action="store_true",
        help="Force re-fetch even if the cache file exists.",
    )
    ap.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Write generated Rust to PATH instead of stdout.",
    )
    args = ap.parse_args()

    if args.source is not None:
        text = args.source.read_text(encoding="utf-8", errors="replace")
    else:
        text = fetch_pci_ids(args.cache, args.refresh)

    db = parse_pci_ids(text)

    if args.overlay is not None:
        overlay_text = args.overlay.read_text(encoding="utf-8", errors="replace")
        db.merge(parse_pci_ids(overlay_text))

    rust = build_variants_from_db(db)

    if args.output is None:
        sys.stdout.write(rust)
    else:
        args.output.write_text(rust, encoding="utf-8")
        print(
            f"[pci_ids] wrote {args.output} "
            f"({len(rust.splitlines())} lines, {len(db.vendors)} vendors, "
            f"{sum(len(v) for v in db.devices.values())} devices, "
            f"{len(db.classes)} classes)",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
