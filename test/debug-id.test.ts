import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readExecutableDebugId, selectDebugFile } from "../backend/debug-id";
import type { Arch } from "../lib/util";

const dir = mkdtempSync(join(tmpdir(), "bun-report-debug-id-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

function file(name: string, contents: Buffer): string {
  const path = join(dir, name);
  writeFileSync(path, contents);
  return path;
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
}
function u16(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n);
  return b;
}
function u64(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
}
/** Lays `parts` out at the given absolute offsets in a zero-filled buffer. */
function layout(size: number, parts: [offset: number, bytes: Buffer][]): Buffer {
  const out = Buffer.alloc(size);
  for (const [offset, bytes] of parts) bytes.copy(out, offset);
  return out;
}

describe("readExecutableDebugId", () => {
  test("ELF: descriptor of the NT_GNU_BUILD_ID note, skipping other notes", () => {
    const build_id = "caac16c6401beba3fdd7e29cafe9bd212a0a23f8"; // readelf -n of a real bun-debug
    const note = (type: number, desc: Buffer) =>
      Buffer.concat([u32(4), u32(desc.length), u32(type), Buffer.from("GNU\0", "latin1"), desc]);
    const notes = Buffer.concat([
      note(1 /* NT_GNU_ABI_TAG */, Buffer.alloc(16, 0xaa)),
      note(3 /* NT_GNU_BUILD_ID */, Buffer.from(build_id, "hex")),
    ]);
    const notes_offset = 64 + 2 * 56;
    const elf = layout(notes_offset + notes.length, [
      [0, Buffer.from("\x7fELF", "latin1")],
      [0x20, u64(64)], // e_phoff
      [0x36, u16(56)], // e_phentsize
      [0x38, u16(2)], // e_phnum
      // phdr 0: PT_LOAD, must be ignored.
      [64, u32(1)],
      // phdr 1: PT_NOTE at notes_offset.
      [64 + 56, u32(4)],
      [64 + 56 + 8, u64(notes_offset)],
      [64 + 56 + 32, u64(notes.length)],
      [notes_offset, notes],
    ]);
    expect(readExecutableDebugId(file("a.elf", elf))).toBe(build_id);
  });

  test("ELF without a build-id note", () => {
    const elf = layout(64, [
      [0, Buffer.from("\x7fELF", "latin1")],
      [0x20, u64(64)],
      [0x36, u16(56)],
      [0x38, u16(0)],
    ]);
    expect(readExecutableDebugId(file("no-note.elf", elf))).toBeUndefined();
  });

  test("PE: CodeView GUID in the order llvm-readobj and dumpbin print it", () => {
    // llvm-readobj --coff-debug-directory on a real bun-debug.exe printed
    // PDBGUID: {94466803-4EEA-D862-4C4C-44205044422E}; these are the bytes as
    // they sit in the file (the first three fields little-endian).
    const guid_in_file = Buffer.from("03684694" + "ea4e" + "62d8" + "4c4c44205044422e", "hex");
    const code_view = Buffer.concat([
      Buffer.from("RSDS", "latin1"),
      guid_in_file,
      u32(1),
      Buffer.from("bun.pdb\0", "latin1"),
    ]);

    const pe_offset = 64;
    const optional_header_size = 112 + 16 * 8;
    const optional_header = pe_offset + 24;
    const section_table = optional_header + optional_header_size;
    const section_rva = 0x1000;
    const section_file_offset = 512;
    const entry_size = 28;
    const code_view_offset = section_file_offset + 2 * entry_size;

    const pe = layout(code_view_offset + code_view.length, [
      [0, Buffer.from("MZ", "latin1")],
      [0x3c, u32(pe_offset)],
      [pe_offset, Buffer.from("PE\0\0", "latin1")],
      [pe_offset + 4 + 2, u16(1)], // NumberOfSections
      [pe_offset + 4 + 16, u16(optional_header_size)],
      [optional_header, u16(0x20b)],
      [optional_header + 108, u32(16)], // NumberOfRvaAndSizes
      [optional_header + 112 + 6 * 8, u32(section_rva)], // debug directory rva...
      [optional_header + 112 + 6 * 8 + 4, u32(2 * entry_size)], // ...and size
      [section_table + 12, u32(section_rva)], // VirtualAddress
      [section_table + 16, u32(0x200)], // SizeOfRawData
      [section_table + 20, u32(section_file_offset)], // PointerToRawData
      // entry 0: IMAGE_DEBUG_TYPE_COFF, must be skipped.
      [section_file_offset + 12, u32(1)],
      // entry 1: CodeView.
      [section_file_offset + entry_size + 12, u32(2)],
      [section_file_offset + entry_size + 24, u32(code_view_offset)],
      [code_view_offset, code_view],
    ]);
    expect(readExecutableDebugId(file("a.exe", pe))).toBe("944668034eead8624c4c44205044422e");
  });

  test("PE without a debug directory", () => {
    const pe = layout(64 + 24 + 240, [
      [0, Buffer.from("MZ", "latin1")],
      [0x3c, u32(64)],
      [64, Buffer.from("PE\0\0", "latin1")],
      [64 + 4 + 16, u16(240)],
      [88, u16(0x20b)],
      [88 + 108, u32(16)],
    ]);
    expect(readExecutableDebugId(file("no-debug.exe", pe))).toBeUndefined();
  });

  test("Mach-O: LC_UUID bytes in order, after other load commands", () => {
    const uuid = "0123456789abcdef0123456789abcdef";
    const segment = layout(72, [
      [0, u32(0x19 /* LC_SEGMENT_64 */)],
      [4, u32(72)],
    ]);
    const uuid_command = Buffer.concat([u32(0x1b), u32(24), Buffer.from(uuid, "hex")]);
    const commands = Buffer.concat([segment, uuid_command]);
    const macho = layout(32 + commands.length, [
      [0, u32(0xfeedfacf)],
      [16, u32(2)], // ncmds
      [20, u32(commands.length)], // sizeofcmds
      [32, commands],
    ]);
    expect(readExecutableDebugId(file("a.macho", macho))).toBe(uuid);
  });

  test("not an executable, or not there at all", () => {
    expect(
      readExecutableDebugId(file("features.json", Buffer.from('{"features":[]}'))),
    ).toBeUndefined();
    expect(readExecutableDebugId(file("tiny", Buffer.from("MZ")))).toBeUndefined();
    expect(readExecutableDebugId(join(dir, "does-not-exist"))).toBeUndefined();
  });

  test("the binary running this test has an id of a plausible shape", () => {
    // bun's own releases are linked with a build-id / PDB / LC_UUID, so this
    // exercises the real-file path on whichever platform the tests run.
    expect(readExecutableDebugId(process.execPath)).toMatch(/^[0-9a-f]{32}([0-9a-f]{8})?$/);
  });
});

describe("selectDebugFile", () => {
  interface Info {
    arch: Arch;
    debug_id: string | undefined;
  }
  const A = "aa".repeat(16);
  const B = "bb".repeat(16);

  function unavailable(arch: Arch): Error & { code: string } {
    return Object.assign(new Error(`no artifact for ${arch}`), { code: "DebugInfoUnavailable" });
  }

  /** `store` maps each published arch to the id its executable carries (undefined = unreadable). */
  function bucket(store: Partial<Record<Arch, string | undefined | Error>>) {
    const fetched: Arch[] = [];
    const fetch = async (arch: Arch): Promise<Info> => {
      fetched.push(arch);
      if (!(arch in store)) throw unavailable(arch);
      const entry = store[arch];
      if (entry instanceof Error) throw entry;
      return { arch, debug_id: entry };
    };
    return { fetch, fetched };
  }

  test("a trace without an id uses its own arch unchecked, as before", async () => {
    const { fetch, fetched } = bucket({ x86_64: A, x86_64_baseline: B });
    expect(await selectDebugFile("x86_64", undefined, fetch)).toEqual({
      arch: "x86_64",
      debug_id: A,
    });
    expect(fetched).toEqual(["x86_64"]);
  });

  test("a trace without an id still fails when its own arch is missing", async () => {
    const { fetch } = bucket({ x86_64_baseline: B });
    await expect(selectDebugFile("x86_64", undefined, fetch)).rejects.toMatchObject({
      code: "DebugInfoUnavailable",
    });
  });

  test("the trace's own arch carries the id", async () => {
    const { fetch, fetched } = bucket({ x86_64: A, x86_64_baseline: B });
    expect(await selectDebugFile("x86_64", A, fetch)).toEqual({
      arch: "x86_64",
      debug_id: A,
      debug_file: "match",
    });
    expect(fetched).toEqual(["x86_64"]);
  });

  test("the other x64 link carries the id (the bun-windows-x64 vs -baseline case)", async () => {
    const { fetch, fetched } = bucket({ x86_64: A, x86_64_baseline: B });
    expect(await selectDebugFile("x86_64", B, fetch)).toEqual({
      arch: "x86_64_baseline",
      debug_id: B,
      debug_file: "match",
    });
    expect(fetched).toEqual(["x86_64", "x86_64_baseline"]);
  });

  test("works in the other direction too", async () => {
    const { fetch } = bucket({ x86_64: A, x86_64_baseline: B });
    expect(await selectDebugFile("x86_64_baseline", A, fetch)).toMatchObject({
      arch: "x86_64",
      debug_file: "match",
    });
  });

  test("no published link carries the id: the trace's own arch, flagged mismatch", async () => {
    const { fetch } = bucket({ x86_64: A, x86_64_baseline: B });
    expect(await selectDebugFile("x86_64", "cc".repeat(16), fetch)).toEqual({
      arch: "x86_64",
      debug_id: A,
      debug_file: "mismatch",
    });
  });

  test("a missing sibling is skipped, not an error", async () => {
    const { fetch } = bucket({ x86_64: A });
    expect(await selectDebugFile("x86_64", B, fetch)).toMatchObject({
      arch: "x86_64",
      debug_file: "mismatch",
    });
  });

  test("an arch with no siblings goes straight to mismatch", async () => {
    const { fetch, fetched } = bucket({ aarch64: A });
    expect(await selectDebugFile("aarch64", B, fetch)).toMatchObject({
      arch: "aarch64",
      debug_file: "mismatch",
    });
    expect(fetched).toEqual(["aarch64"]);
  });

  test("an artifact whose executable has no readable id is used unverified", async () => {
    const { fetch, fetched } = bucket({ x86_64: undefined, x86_64_baseline: B });
    expect(await selectDebugFile("x86_64", B, fetch)).toEqual({
      arch: "x86_64",
      debug_id: undefined,
      debug_file: "unverified",
    });
    expect(fetched).toEqual(["x86_64"]);
  });

  test("the trace's own arch was never published but a sibling carrying the id was", async () => {
    const { fetch } = bucket({ x86_64_baseline: B });
    expect(await selectDebugFile("x86_64", B, fetch)).toMatchObject({
      arch: "x86_64_baseline",
      debug_file: "match",
    });
  });

  test("nothing published at all reports the trace's own arch as unavailable", async () => {
    const { fetch } = bucket({});
    await expect(selectDebugFile("x86_64", B, fetch)).rejects.toMatchObject({
      code: "DebugInfoUnavailable",
      message: "no artifact for x86_64",
    });
  });

  test("errors other than a missing artifact propagate", async () => {
    const boom = new Error("unzip exploded");
    await expect(selectDebugFile("x86_64", B, bucket({ x86_64: boom }).fetch)).rejects.toBe(boom);
    await expect(
      selectDebugFile("x86_64", B, bucket({ x86_64: A, x86_64_baseline: boom }).fetch),
    ).rejects.toBe(boom);
  });
});
