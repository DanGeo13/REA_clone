import { describe, expect, it } from "vitest";
import { FirmwareVectorTableService } from "./FirmwareVectorTableService.js";
import { FIRMWARE_VECTOR_TABLE_PROVIDER } from "../../domain/investigationProviders.js";
import { decodeLimit } from "../../domain/parseFailure.js";
import { parseLimitConstraint } from "../../domain/parseFailureAnalysisError.js";
import { firmwareVectorBudgetLimit } from "../../domain/firmware/firmwareVectorTable.js";
import { err, ok } from "../../domain/result.js";
import type { FirmwareVectorTablePort } from "../../ports/binaryDiagnostics/FirmwareVectorTablePort.js";

describe("FirmwareVectorTableService", () => {
  it("records sha256-bound Evidence, file-offset-range location, and hashed svd_xml provenance", async () => {
    const mockPort: FirmwareVectorTablePort = {
      identity: FIRMWARE_VECTOR_TABLE_PROVIDER,
      inspect: async (input) =>
        ok({
          artifact: {
            path: input.path,
            sha256: "e".repeat(64),
            bytes: 256,
          },
          architecture: "armv7-m",
          base_address: "0x8000000",
          vector_table_offset: 64,
          vector_table_address: "0x8000040",
          vtor_aligned: false,
          examined_entries: 4,
          table_file_range: { start: 64, end: 80 },
          coverage: {
            status: "partial",
            examined_bytes: 16,
            available_from_offset_bytes: 192,
          },
          initial_stack_pointer: "0x20010000",
          reset_code_address: "0x8000100",
          riscv_table_shape: null,
          arm_entries: [],
          riscv_slots: [],
          shared_handler_groups: [],
          svd_interrupts: {
            supplied: true,
            mapped_irq_count: 0,
            ambiguous_irq_count: 0,
            unmapped_active_irq_count: 0,
          },
          anomalies: [],
          limitations: ["Decoded 4 slots up to max_entries."],
        }),
    };

    const service = new FirmwareVectorTableService(mockPort);
    const res = await service.inspect({
      path: "/tmp/stm32.bin",
      architecture: "armv7-m",
      base_address: "0x08000000",
      vector_table_offset: 64,
      max_entries: 4,
      svd_xml: "<device><peripherals/></device>",
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.operation).toBe("inspect_firmware_vector_table");
    expect(res.value.subject.identity).toMatchObject({
      kind: "file",
      sha256: "e".repeat(64),
    });
    expect(res.value.parameters).not.toHaveProperty("svd_xml");
    expect(res.value.parameters).toHaveProperty("svd_xml_sha256");
    expect(res.value.locations).toEqual([
      { kind: "artifact-path", path: "/tmp/stm32.bin" },
      { kind: "file-offset-range", start: 64, end: 80 },
    ]);
  });

  it("propagates parameter limit refusals with control_kind: parameter", async () => {
    const mockPort: FirmwareVectorTablePort = {
      identity: FIRMWARE_VECTOR_TABLE_PROVIDER,
      inspect: async (input) =>
        err(
          parseLimitConstraint(
            "inspect_firmware_vector_table",
            "file-size",
            decodeLimit(
              "firmware-vector-table",
              "File exceeds max_file_bytes",
              {
                name: "max_file_bytes",
                maximum: input.max_file_bytes,
              },
            ),
            {
              retryable: false,
              limit: firmwareVectorBudgetLimit(
                "max_file_bytes",
                input.max_file_bytes,
              ),
              remediationAction: "Raise max_file_bytes.",
            },
          ),
        ),
    };
    const service = new FirmwareVectorTableService(mockPort);
    const res = await service.inspect({
      path: "/tmp/huge.bin",
      architecture: "armv7-m",
      base_address: "0x08000000",
      max_file_bytes: 16,
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error.limit).toMatchObject({
      control_kind: "parameter",
      parameter: "max_file_bytes",
      effective_value: 16,
    });
  });
});
