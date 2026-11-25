import { describe, expect, it } from "vitest";
import { buildUImage } from "../../../tests/fixtures/uimage.js";
import {
  firmwareArchitectureCandidatesSchema,
  buildRawBinarySuggestion,
} from "./firmwareArchitectureCandidates.js";
import { scanFirmwareArchitectureCandidates } from "./firmwareArchitectureScanner.js";

const buildMinimalElfHeader = (options: {
  readonly elfClass: 32 | 64;
  readonly littleEndian: boolean;
  readonly machine: number;
  readonly type?: number;
}): Buffer => {
  const size = options.elfClass === 32 ? 52 : 64;
  const buf = Buffer.alloc(size, 0);
  buf[0] = 0x7f;
  buf[1] = 0x45;
  buf[2] = 0x4c;
  buf[3] = 0x46;
  buf[4] = options.elfClass === 32 ? 1 : 2;
  buf[5] = options.littleEndian ? 1 : 2;
  buf[6] = 1;
  const write16 = options.littleEndian
    ? (offset: number, v: number) => buf.writeUInt16LE(v, offset)
    : (offset: number, v: number) => buf.writeUInt16BE(v, offset);
  const write32 = options.littleEndian
    ? (offset: number, v: number) => buf.writeUInt32LE(v, offset)
    : (offset: number, v: number) => buf.writeUInt32BE(v, offset);
  write16(16, options.type ?? 2);
  write16(18, options.machine);
  write32(20, 1);
  write16(options.elfClass === 32 ? 40 : 52, size);
  return buf;
};

const buildCortexMImage = (options?: {
  readonly baseAddress?: number;
  readonly headerPadBytes?: number;
}): Buffer => {
  const base = options?.baseAddress ?? 0x08000000;
  const pad = options?.headerPadBytes ?? 0;
  const image = Buffer.alloc(pad + 512, 0);
  if (pad > 0) image.fill(0xaa, 0, pad);
  const vt = pad;
  image.writeUInt32LE(0x20020000, vt + 0); // Initial SP in SRAM
  image.writeUInt32LE((base + vt + 0x100) | 1, vt + 4); // Reset
  image.writeUInt32LE((base + vt + 0x120) | 1, vt + 8); // NMI
  image.writeUInt32LE((base + vt + 0x124) | 1, vt + 12); // HardFault
  image.writeUInt32LE((base + vt + 0x130) | 1, vt + 44); // SVCall
  image.writeUInt32LE((base + vt + 0x138) | 1, vt + 56); // PendSV
  image.writeUInt32LE((base + vt + 0x140) | 1, vt + 60); // SysTick
  // Emit a few Thumb functions: push {r4, lr} (0xb510), nop (0xbf00), pop {r4, pc} (0xbd10), bx lr (0x4770)
  for (let i = 0; i < 6; i += 1) {
    const fnOff = vt + 0x100 + i * 8;
    image.writeUInt16LE(0xb510, fnOff);
    image.writeUInt16LE(0xbf00, fnOff + 2);
    image.writeUInt16LE(0xbd10, fnOff + 4);
    image.writeUInt16LE(0x4770, fnOff + 6);
  }
  return image;
};

describe("scanFirmwareArchitectureCandidates", () => {
  it("parses embedded U-Boot uImage headers at non-zero offsets and qualifies payload-relative addresses", async () => {
    const prefix = Buffer.alloc(256, 0xff);
    // arch=5 (mips), compression=3 (lzma)
    const uimage = buildUImage({
      arch: 5,
      compression: 3,
      loadAddress: 0x80010000,
      entryPoint: 0x80010400,
      name: "OpenWrt MIPS Kernel",
      payload: Buffer.from("compressed-payload-bytes"),
    });
    const combined = Buffer.concat([prefix, uimage]);
    const report = await scanFirmwareArchitectureCandidates({
      artifact: {
        path: "/tmp/router.bin",
        sha256: "a".repeat(64),
        bytes: combined.length,
      },
      prefixBytes: combined,
    });

    expect(firmwareArchitectureCandidatesSchema.safeParse(report).success).toBe(
      true,
    );
    expect(report.status).toBe("candidates_found");
    expect(report.uimage_headers.total).toBe(1);
    expect(report.uimage_headers.items[0]).toMatchObject({
      file_offset: 256,
      header_end: 320,
      raw_ih_arch: 5,
      ih_arch_name: "mips",
      raw_ih_comp: 3,
      ih_comp_name: "lzma",
      load_address: "0x80010000",
      entry_point: "0x80010400",
      image_name: "OpenWrt MIPS Kernel",
    });
    expect(report.uimage_headers.items[0]?.payload_mapping_note).toContain(
      "after the 64-byte uImage header",
    );
    expect(report.candidates[0]).toMatchObject({
      rank: 1,
      cpu_family: "mips",
      word_size: 32,
      byte_order: "unknown",
      detector: "uimage-header",
      confidence: "derived",
      raw_binary_support: {
        admitted_today: false,
        open_binary_arguments: null,
        rizin_decoder_hint: { asm_arch: "mips", asm_bits: 32 },
      },
    });
  });

  it("tallies embedded ELF headers and reports mixed rather than a false winner when tied", async () => {
    const mipsBe1 = buildMinimalElfHeader({
      elfClass: 32,
      littleEndian: false,
      machine: 8, // EM_MIPS
    });
    const mipsBe2 = buildMinimalElfHeader({
      elfClass: 32,
      littleEndian: false,
      machine: 8,
    });
    const armLe = buildMinimalElfHeader({
      elfClass: 32,
      littleEndian: true,
      machine: 40, // EM_ARM
    });

    const majorityBlob = Buffer.concat([
      Buffer.alloc(32, 0),
      mipsBe1,
      Buffer.alloc(64, 0),
      mipsBe2,
      Buffer.alloc(64, 0),
      armLe,
    ]);
    const majorityReport = await scanFirmwareArchitectureCandidates({
      artifact: {
        path: "/tmp/rootfs.bin",
        sha256: "b".repeat(64),
        bytes: majorityBlob.length,
      },
      prefixBytes: majorityBlob,
    });
    expect(majorityReport.elf_census.consensus).toBe("majority");
    expect(majorityReport.candidates[0]).toMatchObject({
      cpu_family: "mips",
      word_size: 32,
      byte_order: "big",
      detector: "embedded-elf-census",
      confidence: "observed",
    });

    const tiedBlob = Buffer.concat([mipsBe1, Buffer.alloc(32, 0), armLe]);
    const tiedReport = await scanFirmwareArchitectureCandidates({
      artifact: {
        path: "/tmp/mixed.bin",
        sha256: "c".repeat(64),
        bytes: tiedBlob.length,
      },
      prefixBytes: tiedBlob,
    });
    expect(tiedReport.elf_census.consensus).toBe("mixed");
    expect(
      tiedReport.candidates.some((c) => c.detector === "embedded-elf-census"),
    ).toBe(false);
    expect(
      tiedReport.limitations.some((l) => l.includes("no strict majority")),
    ).toBe(true);
  });
});

describe("scanFirmwareArchitectureCandidates Cortex-M vector tables", () => {
  it("detects ARM M-profile vector tables and derives STM32 0x08000000 and RP2040 0x10000000+0x100 load bases", async () => {
    const stm32 = buildCortexMImage({ baseAddress: 0x08000000 });
    const stmReport = await scanFirmwareArchitectureCandidates({
      artifact: {
        path: "/tmp/stm32.bin",
        sha256: "d".repeat(64),
        bytes: stm32.length,
      },
      prefixBytes: stm32,
    });
    const vtCandidate = stmReport.candidates.find(
      (c) => c.detector === "cortex-m-vector-table",
    );
    expect(vtCandidate).toBeDefined();
    expect(vtCandidate?.load_base_candidates?.[0]).toMatchObject({
      table_file_offset: 0,
      base_address: "0x8000000",
      vector_table_address: "0x8000000",
      initial_sp: "0x20020000",
      reset_code_address: "0x8000100",
    });
    expect(vtCandidate?.raw_binary_support).toMatchObject({
      admitted_today: true,
      open_binary_arguments: {
        format: "raw-binary",
        architecture: "arm",
        architecture_variant: "armv7-m",
        base_address: "0x8000000",
        entry_point_required: false,
      },
    });

    const rp2040 = buildCortexMImage({
      baseAddress: 0x10000000,
      headerPadBytes: 0x100, // 256-byte boot2 stage
    });
    const rpReport = await scanFirmwareArchitectureCandidates({
      artifact: {
        path: "/tmp/rp2040.bin",
        sha256: "e".repeat(64),
        bytes: rp2040.length,
      },
      prefixBytes: rp2040,
    });
    const rpVt = rpReport.candidates.find(
      (c) => c.detector === "cortex-m-vector-table",
    );
    expect(rpVt?.load_base_candidates?.[0]).toMatchObject({
      table_file_offset: 0x100,
      base_address: "0x10000000",
      vector_table_address: "0x10000100",
    });
    expect(rpVt?.raw_binary_support.open_binary_arguments).toMatchObject({
      base_address: "0x10000000",
      vector_table_address: "0x10000100",
    });
  });
});

describe("scanFirmwareArchitectureCandidates instruction census and controls", () => {
  it("identifies AArch64 and big-endian PowerPC blobs from prologue/return censuses with runner-up margins", async () => {
    const aarch64 = Buffer.alloc(128, 0);
    for (let i = 0; i < 5; i += 1) {
      const base = i * 16;
      aarch64.writeUInt32LE(0xa9bf7bfd, base); // stp x29, x30, [sp, #-16]!
      aarch64.writeUInt32LE(0xd503233f, base + 4); // paciasp
      aarch64.writeUInt32LE(0xd65f03c0, base + 8); // ret
    }
    const arm64Report = await scanFirmwareArchitectureCandidates({
      artifact: {
        path: "/tmp/bl31.bin",
        sha256: "1".repeat(64),
        bytes: aarch64.length,
      },
      prefixBytes: aarch64,
    });
    expect(arm64Report.instruction_census.leader_profile_id).toBe("arm64-le");
    expect(arm64Report.instruction_census.margin_hits).toBeGreaterThanOrEqual(
      10,
    );
    expect(arm64Report.candidates[0]).toMatchObject({
      cpu_family: "arm64",
      word_size: 64,
      byte_order: "little",
      detector: "instruction-signature-census",
      confidence: "inferred",
      raw_binary_support: {
        admitted_today: true,
        open_binary_arguments: {
          format: "raw-binary",
          architecture: "arm64",
          entry_point_required: true,
        },
      },
    });

    const ppc = Buffer.alloc(128, 0);
    for (let i = 0; i < 4; i += 1) {
      const base = i * 16;
      ppc.writeUInt32BE(0x9421ffe0, base); // stwu r1, -32(r1)
      ppc.writeUInt32BE(0x7c0802a6, base + 4); // mflr r0
      ppc.writeUInt32BE(0x4e800020, base + 8); // blr
    }
    const ppcReport = await scanFirmwareArchitectureCandidates({
      artifact: {
        path: "/tmp/uboot-ppc.bin",
        sha256: "2".repeat(64),
        bytes: ppc.length,
      },
      prefixBytes: ppc,
    });
    expect(ppcReport.instruction_census.leader_profile_id).toBe("powerpc-be");
    expect(ppcReport.candidates[0]).toMatchObject({
      cpu_family: "powerpc",
      byte_order: "big",
      raw_binary_support: { admitted_today: false },
    });
  });

  it("returns explicit unknown for deterministic PRNG, zero-filled, and 0xFF erased flash controls", async () => {
    const prng = Buffer.alloc(65536);
    let state = 0x12345678;
    for (let i = 0; i < prng.length; i += 1) {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      prng[i] = state & 0xff;
    }

    for (const [label, buf] of [
      ["prng", prng],
      ["zeros", Buffer.alloc(8192, 0x00)],
      ["erased", Buffer.alloc(8192, 0xff)],
    ] as const) {
      const report = await scanFirmwareArchitectureCandidates({
        artifact: {
          path: `/tmp/${label}.bin`,
          sha256: "f".repeat(64),
          bytes: buf.length,
        },
        prefixBytes: buf,
      });
      expect(report.status).toBe("unknown");
      expect(report.candidates).toEqual([]);
      expect(report.detectors).toHaveLength(4);
      expect(report.coverage).toEqual({
        status: "complete",
        examined_bytes: buf.length,
        total_bytes: buf.length,
      });
    }
  });

  it("maps m68k big-endian to raw-binary and leaves unknown-endianness arm unconfirmed", () => {
    expect(
      buildRawBinarySuggestion({
        cpuFamily: "m68k",
        byteOrder: "big",
        wordSize: 32,
      }),
    ).toMatchObject({
      admitted_today: true,
      open_binary_arguments: {
        format: "raw-binary",
        architecture: "m68k",
        entry_point_required: true,
      },
    });
    expect(
      buildRawBinarySuggestion({
        cpuFamily: "arm",
        byteOrder: "unknown",
        wordSize: 32,
      }),
    ).toMatchObject({
      admitted_today: false,
      open_binary_arguments: null,
    });
  });
});
