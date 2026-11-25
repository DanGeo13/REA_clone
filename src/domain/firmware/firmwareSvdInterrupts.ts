import type { Element } from "@xmldom/xmldom";
import {
  decodeLimit,
  malformedInput,
  type ParseFailureError,
} from "../parseFailure.js";
import { err, ok, type Result } from "../result.js";
import {
  parseXmlDocumentWithinNodeLimit,
  xmlChildrenNamed,
  xmlFirstChildNamed,
} from "../xmlDocument.js";
import { MAX_SVD_XML_NODES } from "./firmwareVectorTable.js";

export interface SvdInterruptCandidate {
  readonly irqNumber: number;
  readonly interruptName: string;
  readonly peripheralName: string;
}

export interface SvdIrqLookupEntry {
  readonly irqNumber: number;
  readonly primaryName: string | null;
  readonly primaryPeripheral: string | null;
  readonly ambiguousNames: readonly string[];
}

export type SvdInterruptParseError =
  | ParseFailureError<"malformed">
  | ParseFailureError<"unsupported">
  | ParseFailureError<"limit">;

const trimmedText = (element: Element | undefined): string | null => {
  if (element === undefined) return null;
  const text = (element.textContent ?? "").trim();
  return text.length > 0 ? `${text}` : null;
};

const parseNonNegativeInt = (raw: string): number | null => {
  const normalized = raw.trim();
  if (/^0x[0-9a-fA-F]+$/u.test(normalized)) {
    const parsed = Number.parseInt(normalized.slice(2), 16);
    return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
  }
  if (/^[0-9]+$/u.test(normalized)) {
    const parsed = Number.parseInt(normalized, 10);
    return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
  }
  return null;
};

const extractPeripheralInterrupts = (
  peripheralEl: Element,
  peripheralName: string,
): SvdInterruptCandidate[] => {
  const out: SvdInterruptCandidate[] = [];
  for (const intEl of xmlChildrenNamed(peripheralEl, "interrupt")) {
    const intName = trimmedText(xmlFirstChildNamed(intEl, "name"));
    const valueText = trimmedText(xmlFirstChildNamed(intEl, "value"));
    if (intName === null || valueText === null) continue;
    const irqNumber = parseNonNegativeInt(valueText);
    if (irqNumber === null) continue;
    out.push({ irqNumber, interruptName: intName, peripheralName });
  }
  return out;
};

/** Parse CMSIS-SVD `<peripheral><interrupt>` bindings without external DTDs. */
export const parseSvdInterruptMap = (
  svdXml: string,
): Result<ReadonlyMap<number, SvdIrqLookupEntry>, SvdInterruptParseError> => {
  const docResult = parseXmlDocumentWithinNodeLimit(svdXml, {
    maximumNodes: MAX_SVD_XML_NODES,
    lineEndings: "normalize",
  });
  if (!docResult.ok) {
    const failure = docResult.error;
    if ("kind" in failure && failure.kind === "node-limit") {
      return err(
        decodeLimit(
          "cmsis-svd",
          `svd_xml exceeded the ${String(failure.maximum)}-node XML ceiling`,
          { name: "svd_xml", maximum: failure.maximum },
        ),
      );
    }
    return err(failure);
  }

  const root = docResult.value.documentElement;
  if (root === null || root.localName !== "device") {
    return err(
      malformedInput("cmsis-svd", "CMSIS-SVD root element must be <device>."),
    );
  }

  const peripheralsEl = xmlFirstChildNamed(root, "peripherals");
  if (peripheralsEl === undefined) {
    return ok(new Map());
  }

  const rawByIrq = new Map<number, SvdInterruptCandidate[]>();
  for (const periphEl of xmlChildrenNamed(peripheralsEl, "peripheral")) {
    const periphName = trimmedText(xmlFirstChildNamed(periphEl, "name"));
    if (periphName === null) continue;
    for (const item of extractPeripheralInterrupts(periphEl, periphName)) {
      const existing = rawByIrq.get(item.irqNumber);
      if (existing === undefined) {
        rawByIrq.set(item.irqNumber, [item]);
      } else if (
        !existing.some(
          (e) =>
            e.interruptName === item.interruptName &&
            e.peripheralName === item.peripheralName,
        )
      ) {
        existing.push(item);
      }
    }
  }

  const lookup = new Map<number, SvdIrqLookupEntry>();
  for (const [irqNumber, items] of rawByIrq.entries()) {
    if (items.length === 1) {
      const only = items[0]!;
      lookup.set(irqNumber, {
        irqNumber,
        primaryName: only.interruptName,
        primaryPeripheral: only.peripheralName,
        ambiguousNames: [],
      });
    } else {
      lookup.set(irqNumber, {
        irqNumber,
        primaryName: null,
        primaryPeripheral: null,
        ambiguousNames: items.map(
          (c) => `${c.peripheralName}:${c.interruptName}`,
        ),
      });
    }
  }
  return ok(lookup);
};
