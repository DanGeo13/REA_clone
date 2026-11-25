import { decodeLimit } from "../../domain/parseFailure.js";
import {
  isParseLimit,
  parseLimitConstraint,
} from "../../domain/parseFailureAnalysisError.js";
import {
  ArtifactResourceScope,
  artifactFilePrimaryFacts,
  assertArtifactReadActive,
  projectArtifactCloseFailure,
  projectStableArtifactFailure,
  readStableArtifact,
  type StableArtifactSnapshot,
} from "../../resources/index.js";
import type { ExecutionOptions } from "../../ports/AnalysisProvider.js";
import type { FirmwareVectorTablePort } from "../../ports/binaryDiagnostics/FirmwareVectorTablePort.js";
import {
  MAX_SVD_XML_NODES,
  MAX_VECTOR_TABLE_FILE_BYTES,
  firmwareVectorBudgetLimit,
  type InspectFirmwareVectorTableInput,
} from "../../domain/firmware/firmwareVectorTable.js";
import { parseSvdInterruptMap } from "../../domain/firmware/firmwareSvdInterrupts.js";
import { parseFirmwareVectorTable } from "../../domain/firmware/firmwareVectorTableParser.js";
import { FIRMWARE_VECTOR_TABLE_PROVIDER } from "../../domain/investigationProviders.js";
import { err, ok } from "../../domain/result.js";
import { classifyProviderFailure } from "../../providers/classifyProviderFailure.js";
import { offlineArtifactFailureDialect } from "../../providers/offlineArtifactFailure.js";

const OPERATION = "inspect_firmware_vector_table";

/** Portable ARM M-profile and RISC-V vector/trap table decoder over one regular file. */
export class FirmwareVectorTableProvider implements FirmwareVectorTablePort {
  readonly identity = FIRMWARE_VECTOR_TABLE_PROVIDER;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw projectArtifactCloseFailure(
        cause,
        FIRMWARE_VECTOR_TABLE_PROVIDER.id,
        OPERATION,
      );
    }
  }

  async inspect(
    input: InspectFirmwareVectorTableInput,
    options?: ExecutionOptions,
  ) {
    let snapshot: StableArtifactSnapshot | undefined;
    try {
      return await this.#resources.run(async () => {
        assertArtifactReadActive(options?.signal);
        const svdResult =
          input.svd_xml === undefined
            ? ok(new Map())
            : parseSvdInterruptMap(input.svd_xml);
        if (!svdResult.ok) throw svdResult.error;

        snapshot = await readStableArtifact(
          input.path,
          input.max_file_bytes,
          options?.signal,
          undefined,
          this.#resources,
        );
        assertArtifactReadActive(options?.signal);

        const sliceEnd = Math.min(
          snapshot.bytes.length,
          input.vector_table_offset + input.max_entries * 4 + 4,
        );
        const tableSlice =
          input.vector_table_offset < snapshot.bytes.length
            ? snapshot.bytes.subarray(input.vector_table_offset, sliceEnd)
            : Buffer.alloc(0);

        const parsed = parseFirmwareVectorTable({
          artifact: {
            path: input.path,
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.length,
          },
          architecture: input.architecture,
          baseAddressHex: input.base_address,
          vectorTableOffset: input.vector_table_offset,
          maxEntries: input.max_entries,
          tableBytes: tableSlice,
          svdSupplied: input.svd_xml !== undefined,
          svdMap: svdResult.value,
        });
        if (!parsed.ok) throw parsed.error;
        return ok(parsed.value);
      });
    } catch (cause) {
      return err(vectorTableFailure(cause, input, snapshot));
    }
  }
}

const fileSizeRemediation = (input: InspectFirmwareVectorTableInput): string =>
  input.max_file_bytes >= MAX_VECTOR_TABLE_FILE_BYTES
    ? `The image exceeds the ${String(MAX_VECTOR_TABLE_FILE_BYTES)}-byte input ceiling this operation accepts; select a smaller firmware slice.`
    : `Raise max_file_bytes above ${String(input.max_file_bytes)} bytes within its ${String(MAX_VECTOR_TABLE_FILE_BYTES)}-byte ceiling, or select a smaller firmware slice.`;

const vectorTableFailure = (
  cause: unknown,
  input: InspectFirmwareVectorTableInput,
  snapshot: StableArtifactSnapshot | undefined,
) => {
  const facts = artifactFilePrimaryFacts(cause);
  const primary = classifyProviderFailure(
    facts.cause,
    offlineArtifactFailureDialect(facts, {
      providerId: FIRMWARE_VECTOR_TABLE_PROVIDER.id,
      operation: OPERATION,
      path: input.path,
      description: "firmware vector table",
      fallbackMessage: "Firmware vector table inspection failed.",
      recognise: (failure) => {
        if (isParseLimit(failure, "cmsis-svd")) {
          return parseLimitConstraint(OPERATION, "capacity", failure, {
            retryable: false,
            limit: firmwareVectorBudgetLimit("svd_xml", MAX_SVD_XML_NODES),
            remediationAction: `Provide a trimmed CMSIS-SVD document within the ${String(MAX_SVD_XML_NODES)}-node XML ceiling.`,
          });
        }
        return undefined;
      },
      fileSize: (failure) =>
        parseLimitConstraint(
          OPERATION,
          "file-size",
          decodeLimit(
            "firmware-vector-table",
            failure.message,
            { name: "max_file_bytes", maximum: input.max_file_bytes },
            { cause: failure },
          ),
          {
            retryable: false,
            limit: firmwareVectorBudgetLimit(
              "max_file_bytes",
              input.max_file_bytes,
            ),
            remediationAction: fileSizeRemediation(input),
          },
        ),
    }),
  );
  return projectStableArtifactFailure(
    cause,
    primary,
    input.path,
    FIRMWARE_VECTOR_TABLE_PROVIDER.id,
    OPERATION,
    snapshot,
  );
};
