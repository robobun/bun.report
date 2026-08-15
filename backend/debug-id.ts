import { closeSync, openSync, readSync } from "node:fs";
import type { Arch } from "../lib/util";

// Deliberately free of backend imports (db, git, ...) so the selection policy
// below is unit-testable; debug-store.ts supplies the downloading.

export interface DebugFileCheck {
  /** Set only when the trace carried a debug id to check against. See `Remap.debug_file`. */
  debug_file?: "match" | "mismatch" | "unverified";
}

/**
 * The other links a commit may be published as for the same os. A v4 trace
 * says `'w'` for both Windows x64 links of a commit when the build that made
 * it did not know which zip it would ship in, so the debug id decides.
 */
const sibling_archs: Partial<Record<Arch, readonly Arch[]>> = {
  x86_64: ["x86_64_baseline"],
  x86_64_baseline: ["x86_64"],
};

function isUnavailable(e: unknown): boolean {
  return (e as any)?.code === "DebugInfoUnavailable";
}

/**
 * Which of a commit's links to symbolize a trace with. `fetch(arch)` yields
 * that arch's artifact (with the id read from its executable, if readable)
 * or throws `DebugInfoUnavailable` when the commit was not published under
 * that name.
 *
 * - no trace id (formats 1-3): the trace's own arch, unchecked, as before.
 * - it matches the trace's arch artifact: use it.
 * - that artifact's id is unreadable: use it, flagged "unverified" (there is
 *   no evidence either way, so behave as before).
 * - otherwise try the sibling links; the one carrying the id wins and a
 *   missing sibling is skipped. When the trace's own artifact is missing
 *   altogether this is also how a trace published only under the other
 *   name gets symbolized at all.
 * - nothing carries the id: "mismatch". The caller then leaves the addresses
 *   unsymbolicated; remapping them against another link's debug info is what
 *   produced confidently wrong reports before the id existed.
 */
export async function selectDebugFile<T extends { debug_id: string | undefined }>(
  arch: Arch,
  debug_id: string | undefined,
  fetch: (arch: Arch) => Promise<T>,
): Promise<T & DebugFileCheck> {
  let primary: T | undefined;
  let primary_error: unknown;
  try {
    primary = await fetch(arch);
  } catch (e) {
    if (debug_id === undefined || !isUnavailable(e)) throw e;
    primary_error = e;
  }
  if (debug_id === undefined) return primary!;
  if (primary) {
    if (primary.debug_id === debug_id) return { ...primary, debug_file: "match" };
    if (primary.debug_id === undefined) return { ...primary, debug_file: "unverified" };
  }

  for (const sibling of sibling_archs[arch] ?? []) {
    let candidate: T;
    try {
      candidate = await fetch(sibling);
    } catch (e) {
      if (isUnavailable(e)) continue;
      throw e;
    }
    if (candidate.debug_id === debug_id) return { ...candidate, debug_file: "match" };
  }

  if (primary === undefined) throw primary_error;
  return { ...primary, debug_file: "mismatch" };
}

/**
 * The id a linker stamps into an executable and its debug info, read from the
 * executable shipped in a `*-profile.zip`, in the same form bun's crash
 * handler puts in a v4 trace string (`src/crash_handler/debug_id.rs`):
 * lowercase hex, bytes in the order the platform's tools print them.
 *
 *   PE      CodeView (RSDS) record referenced by the debug data directory:
 *           the PDB GUID, first three fields byte-swapped into textual order.
 *   ELF     descriptor of the NT_GNU_BUILD_ID note in a PT_NOTE segment.
 *   Mach-O  the LC_UUID load command.
 *
 * Returns undefined when the file has no id or is not one of those formats;
 * the caller treats that as "cannot verify", never as a mismatch.
 */
export function readExecutableDebugId(path: string): string | undefined {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    return undefined;
  }
  try {
    const magic = readAt(fd, 0, 4);
    if (magic.toString("latin1") === "\x7fELF") return elfBuildId(fd);
    if (magic.toString("latin1", 0, 2) === "MZ") return peCodeViewGuid(fd);
    if (magic.readUInt32LE(0) === 0xfeedfacf) return machoUuid(fd);
    return undefined;
  } catch {
    return undefined;
  } finally {
    closeSync(fd);
  }
}

function readAt(fd: number, position: number, length: number): Buffer {
  const buffer = Buffer.alloc(length);
  for (let done = 0; done < length; ) {
    const n = readSync(fd, buffer, done, length - done, position + done);
    if (n === 0) throw new Error(`short read at ${position}`);
    done += n;
  }
  return buffer;
}

function elfBuildId(fd: number): string | undefined {
  const header = readAt(fd, 0, 64);
  const phoff = Number(header.readBigUInt64LE(0x20));
  const phentsize = header.readUInt16LE(0x36);
  const phnum = header.readUInt16LE(0x38);
  const phdrs = readAt(fd, phoff, phentsize * phnum);
  for (let n = 0; n < phnum; n++) {
    const phdr = phdrs.subarray(n * phentsize);
    if (phdr.readUInt32LE(0) !== 4 /* PT_NOTE */) continue;
    const notes = readAt(fd, Number(phdr.readBigUInt64LE(8)), Number(phdr.readBigUInt64LE(32)));
    // Elf64_Nhdr {namesz, descsz, type}, then name and descriptor, each padded to 4.
    for (let off = 0; off + 12 <= notes.length; ) {
      const name_size = notes.readUInt32LE(off);
      const desc_size = notes.readUInt32LE(off + 4);
      const type = notes.readUInt32LE(off + 8);
      const desc_start = (off + 12 + name_size + 3) & ~3;
      if (desc_start + desc_size > notes.length) return undefined;
      if (
        type === 3 /* NT_GNU_BUILD_ID */ &&
        notes.toString("latin1", off + 12, off + 12 + name_size) === "GNU\0"
      ) {
        return desc_size > 0
          ? notes.toString("hex", desc_start, desc_start + desc_size)
          : undefined;
      }
      off = (desc_start + desc_size + 3) & ~3;
    }
  }
  return undefined;
}

function peCodeViewGuid(fd: number): string | undefined {
  const pe_offset = readAt(fd, 0x3c, 4).readUInt32LE(0);
  const file_header = readAt(fd, pe_offset, 24);
  if (file_header.toString("latin1", 0, 4) !== "PE\0\0") return undefined;
  const section_count = file_header.readUInt16LE(6);
  const optional_header_size = file_header.readUInt16LE(20);
  const optional_header = readAt(fd, pe_offset + 24, optional_header_size);
  if (optional_header.readUInt16LE(0) !== 0x20b /* PE32+ */) return undefined;
  // IMAGE_OPTIONAL_HEADER64: NumberOfRvaAndSizes at 108, DataDirectory at 112,
  // 8 bytes per entry, IMAGE_DIRECTORY_ENTRY_DEBUG = 6.
  if (optional_header.readUInt32LE(108) <= 6) return undefined;
  const debug_rva = optional_header.readUInt32LE(112 + 6 * 8);
  const debug_size = optional_header.readUInt32LE(112 + 6 * 8 + 4);
  if (debug_rva === 0 || debug_size === 0) return undefined;

  const sections = readAt(fd, pe_offset + 24 + optional_header_size, section_count * 40);
  let debug_offset: number | undefined;
  for (let n = 0; n < section_count; n++) {
    const section = sections.subarray(n * 40);
    const virtual_address = section.readUInt32LE(12);
    if (debug_rva >= virtual_address && debug_rva < virtual_address + section.readUInt32LE(16)) {
      debug_offset = debug_rva - virtual_address + section.readUInt32LE(20);
    }
  }
  if (debug_offset === undefined) return undefined;

  // IMAGE_DEBUG_DIRECTORY (28 bytes): Type at 12, PointerToRawData at 24.
  const entries = readAt(fd, debug_offset, debug_size);
  for (let off = 0; off + 28 <= entries.length; off += 28) {
    if (entries.readUInt32LE(off + 12) !== 2 /* IMAGE_DEBUG_TYPE_CODEVIEW */) continue;
    const pointer = entries.readUInt32LE(off + 24);
    if (pointer === 0) continue;
    const code_view = readAt(fd, pointer, 20);
    if (code_view.toString("latin1", 0, 4) !== "RSDS") continue;
    const g = code_view.subarray(4, 20);
    return Buffer.from([
      g[3],
      g[2],
      g[1],
      g[0],
      g[5],
      g[4],
      g[7],
      g[6],
      ...g.subarray(8, 16),
    ]).toString("hex");
  }
  return undefined;
}

function machoUuid(fd: number): string | undefined {
  const header = readAt(fd, 0, 32);
  const ncmds = header.readUInt32LE(16);
  const commands = readAt(fd, 32, header.readUInt32LE(20));
  for (let n = 0, off = 0; n < ncmds && off + 8 <= commands.length; n++) {
    const size = commands.readUInt32LE(off + 4);
    if (size < 8) return undefined;
    if (commands.readUInt32LE(off) === 0x1b /* LC_UUID */ && size >= 24) {
      return commands.toString("hex", off + 8, off + 24);
    }
    off += size;
  }
  return undefined;
}
