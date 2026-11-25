import { BoundedListCollector } from "../boundedList.js";
import {
  FIRMWARE_DETECTOR_IDS,
  buildRawBinarySuggestion,
  type CortexMLoadBaseCandidate,
  type DetectorRunSummary,
  type FileOffsetRange,
  type FirmwareArchitectureCandidate,
  type FirmwareArchitectureCandidates,
} from "./firmwareArchitectureCandidates.js";
import {
  MAX_SAMPLE_LOCATIONS,
  MAX_VECTOR_SCAN_OFFSET,
  mapUImageArch,
  scanCortexMVectorTableCandidates,
  scanEmbeddedElfHeaders,
  scanUImageHeaders,
} from "./firmwareArchitectureHeaderDetectors.js";
import {
  runInstructionSignatureCensus,
  type InstructionCensusOutcome,
} from "./firmwareArchitectureInstructionCensus.js";

const emptyCandidateReport = (
  artifact: ScanFirmwareCandidatesOptions["artifact"],
): FirmwareArchitectureCandidates => ({
  artifact,
  status: "unknown",
  coverage: { status: "unknown", examined_bytes: 0, total_bytes: 0 },
  detectors: FIRMWARE_DETECTOR_IDS.map((detector) => ({
    detector,
    examined_bytes: 0,
    status: "skipped_empty" as const,
    detail: "Artifact is 0 bytes; no headers or opcodes could be examined.",
  })),
  candidates: [],
  uimage_headers: { total: 0, omitted: 0, items: [] },
  elf_census: { total_valid_headers: 0, consensus: "absent", tallies: [] },
  instruction_census: {
    examined_bytes: 0,
    leader_profile_id: null,
    runner_up_profile_id: null,
    margin_hits: null,
    profiles: [],
  },
  limitations: [
    "File size is 0 bytes; CPU architecture and endianness are unknown.",
  ],
});

const appendElfAndUImageCandidates = (
  unranked: Omit<FirmwareArchitectureCandidate, "rank">[],
  elf: Awaited<ReturnType<typeof scanEmbeddedElfHeaders>>,
  uimage: Awaited<ReturnType<typeof scanUImageHeaders>>,
  limitations: string[],
): void => {
  if (
    (elf.consensus === "unanimous" || elf.consensus === "majority") &&
    elf.tallies[0] !== undefined
  ) {
    const top = elf.tallies[0];
    const ratio =
      elf.consensus === "unanimous"
        ? "All"
        : `${String(top.count)} of ${String(elf.total_valid_headers)}`;
    unranked.push({
      cpu_family: top.cpu_family,
      isa_mode: "standard",
      word_size: top.elf_class,
      byte_order: top.byte_order,
      detector: "embedded-elf-census",
      confidence: "observed",
      rationale: `${ratio} validated ELF headers declare e_machine ${String(top.machine)} (${top.cpu_family}, ${String(top.elf_class)}-bit, ${top.byte_order}-endian).`,
      locations: top.sample_locations,
      omitted_locations: top.omitted_locations,
      raw_binary_support: buildRawBinarySuggestion({
        cpuFamily: top.cpu_family,
        byteOrder: top.byte_order,
        wordSize: top.elf_class,
      }),
    });
  } else if (elf.consensus === "mixed") {
    limitations.push(
      `Embedded ELF census found ${String(elf.total_valid_headers)} valid ELF headers with no strict majority across ${elf.tallies.map((t) => `${t.cpu_family}/${t.byte_order} (${String(t.count)})`).join(", ")}.`,
    );
  }

  const seenUImageArch = new Set<string>();
  for (const item of uimage.items) {
    const mapped = mapUImageArch(item.ih_arch_name);
    if (mapped === null || seenUImageArch.has(item.ih_arch_name)) continue;
    seenUImageArch.add(item.ih_arch_name);
    const locCollector = new BoundedListCollector<FileOffsetRange>(
      MAX_SAMPLE_LOCATIONS,
    );
    for (const m of uimage.items) {
      if (m.ih_arch_name === item.ih_arch_name) {
        locCollector.push({ start: m.file_offset, end: m.header_end });
      }
    }
    const locs = locCollector.toList();
    unranked.push({
      cpu_family: mapped.cpuFamily,
      word_size: mapped.wordSize,
      byte_order: mapped.byteOrder,
      detector: "uimage-header",
      confidence: "derived",
      rationale: `CRC-verified U-Boot uImage header declares ih_arch ${String(item.raw_ih_arch)} (${item.ih_arch_name}), load ${item.load_address}, entry ${item.entry_point}, compression ${item.ih_comp_name}.`,
      locations: [...locs.items],
      omitted_locations: locs.omitted,
      raw_binary_support: buildRawBinarySuggestion({
        cpuFamily: mapped.cpuFamily,
        byteOrder: mapped.byteOrder,
        wordSize: mapped.wordSize,
      }),
    });
  }
};

const appendInferredCodeCandidates = (
  unranked: Omit<FirmwareArchitectureCandidate, "rank">[],
  vectorCandidates: readonly CortexMLoadBaseCandidate[],
  census: InstructionCensusOutcome,
  examined: number,
): void => {
  const firstVt = vectorCandidates[0];
  if (firstVt !== undefined) {
    unranked.push({
      cpu_family: "arm",
      isa_mode: "thumb",
      word_size: 32,
      byte_order: "little",
      detector: "cortex-m-vector-table",
      confidence: "inferred",
      rationale: `128-byte aligned M-profile vector table at file offset 0x${firstVt.table_file_offset.toString(16)} with initial SP ${firstVt.initial_sp}, odd Thumb Reset ${firstVt.reset_vector}, and ${String(firstVt.valid_exception_vectors)} consistent exception vectors; candidate base ${firstVt.base_address}.`,
      locations: vectorCandidates.map((v) => ({
        start: v.table_file_offset,
        end: v.table_file_offset + 64,
      })),
      omitted_locations: 0,
      load_base_candidates: [...vectorCandidates],
      raw_binary_support: buildRawBinarySuggestion({
        cpuFamily: "arm",
        byteOrder: "little",
        wordSize: 32,
        isaMode: "thumb",
        topBaseCandidate: firstVt,
      }),
    });
  }

  if (census.leader !== null) {
    const leader = census.leader;
    const runnerText =
      census.runner_up === null
        ? "no runner-up hits"
        : `runner-up ${census.runner_up.profile_id} (${String(census.runner_up.total_hits)} hits, margin +${String(census.margin_hits ?? 0)})`;
    unranked.push({
      cpu_family: leader.cpu_family,
      isa_mode: leader.isa_mode,
      word_size: leader.word_size,
      byte_order: leader.byte_order,
      detector: "instruction-signature-census",
      confidence: "inferred",
      rationale: `Instruction prologue/return census matched ${String(leader.total_hits)} hits across ${String(leader.distinct_signatures_matched)} signature families (${String(leader.density_per_kib)} hits/KiB; ${runnerText}).`,
      locations: [{ start: 0, end: examined }],
      omitted_locations: 0,
      raw_binary_support: buildRawBinarySuggestion({
        cpuFamily: leader.cpu_family,
        byteOrder: leader.byte_order,
        wordSize: leader.word_size,
        isaMode: leader.isa_mode,
        ...(leader.cpu_family === "arm" &&
        leader.isa_mode === "thumb" &&
        firstVt !== undefined
          ? { topBaseCandidate: firstVt }
          : {}),
      }),
    });
  }
};

const summarizeDetectors = (options: {
  readonly examined: number;
  readonly uimageTotal: number;
  readonly elf: Awaited<ReturnType<typeof scanEmbeddedElfHeaders>>;
  readonly vectorCount: number;
  readonly census: InstructionCensusOutcome;
}): DetectorRunSummary[] => {
  const { examined, uimageTotal, elf, vectorCount, census } = options;
  return [
    {
      detector: "uimage-header",
      examined_bytes: examined,
      status: uimageTotal > 0 ? "matched" : "no_match",
      detail:
        uimageTotal > 0
          ? `Found ${String(uimageTotal)} CRC-verified U-Boot uImage header(s).`
          : "No CRC-verified U-Boot uImage magic (0x27051956) found.",
    },
    {
      detector: "embedded-elf-census",
      examined_bytes: examined,
      status:
        elf.consensus === "absent"
          ? "no_match"
          : elf.consensus === "mixed"
            ? "mixed"
            : "matched",
      detail:
        elf.total_valid_headers === 0
          ? "No valid ELF32/ELF64 headers found."
          : `Validated ${String(elf.total_valid_headers)} ELF header(s); consensus: ${elf.consensus}.`,
    },
    {
      detector: "cortex-m-vector-table",
      examined_bytes: Math.min(examined, MAX_VECTOR_SCAN_OFFSET),
      status: vectorCount > 0 ? "matched" : "no_match",
      detail:
        vectorCount > 0
          ? `Found ${String(vectorCount)} candidate ARM M-profile vector table(s).`
          : "No qualifying 128-byte aligned Cortex-M vector table found.",
    },
    {
      detector: "instruction-signature-census",
      examined_bytes: examined,
      status: census.leader !== null ? "matched" : "no_match",
      detail:
        census.leader !== null
          ? `Top profile ${census.leader.profile_id} (${String(census.leader.total_hits)} hits).`
          : "No instruction profile met the multi-signature prologue/return threshold.",
    },
  ];
};

export interface ScanFirmwareCandidatesOptions {
  readonly artifact: {
    readonly path: string;
    readonly sha256: string;
    readonly bytes: number;
  };
  readonly prefixBytes: Buffer;
  readonly checkActive?: () => void;
}

/** Run all four static CPU/endianness/base detectors over `prefixBytes`. */
export const scanFirmwareArchitectureCandidates = async (
  options: ScanFirmwareCandidatesOptions,
): Promise<FirmwareArchitectureCandidates> => {
  const { artifact, prefixBytes, checkActive } = options;
  if (artifact.bytes === 0) return emptyCandidateReport(artifact);

  const examined = prefixBytes.length;
  const limitations: string[] = [];
  if (examined < artifact.bytes) {
    limitations.push(
      `Examined the leading ${String(examined)} of ${String(artifact.bytes)} bytes (max_scan_bytes); headers or code past that offset were not scanned.`,
    );
  }

  const uimage = await scanUImageHeaders(prefixBytes, examined, checkActive);
  const elf = await scanEmbeddedElfHeaders(
    prefixBytes,
    examined,
    artifact.bytes,
    checkActive,
  );
  checkActive?.();
  const vectorCandidates = scanCortexMVectorTableCandidates(
    prefixBytes,
    examined,
    artifact.bytes,
  );
  const census = await runInstructionSignatureCensus(
    prefixBytes,
    examined,
    checkActive,
  );

  const unranked: Omit<FirmwareArchitectureCandidate, "rank">[] = [];
  appendElfAndUImageCandidates(unranked, elf, uimage, limitations);
  appendInferredCodeCandidates(unranked, vectorCandidates, census, examined);
  const candidates = unranked.map((item, idx) => ({ rank: idx + 1, ...item }));
  if (candidates.length === 0) {
    limitations.push(
      "No verified uImage header, majority ELF header, Cortex-M vector table, or qualifying instruction-signature cluster matched in the examined byte range; architecture remains unknown.",
    );
  }

  return {
    artifact,
    status: candidates.length > 0 ? "candidates_found" : "unknown",
    coverage: {
      status: examined === artifact.bytes ? "complete" : "partial",
      examined_bytes: examined,
      total_bytes: artifact.bytes,
    },
    detectors: summarizeDetectors({
      examined,
      uimageTotal: uimage.total,
      elf,
      vectorCount: vectorCandidates.length,
      census,
    }),
    candidates,
    uimage_headers: uimage,
    elf_census: elf,
    instruction_census: {
      examined_bytes: census.examined_bytes,
      leader_profile_id: census.leader?.profile_id ?? null,
      runner_up_profile_id: census.runner_up?.profile_id ?? null,
      margin_hits: census.margin_hits,
      profiles: [...census.profiles],
    },
    limitations,
  };
};
