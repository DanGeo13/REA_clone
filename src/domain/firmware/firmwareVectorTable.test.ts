import { describe, expect, it } from "vitest";
import { parseSvdInterruptMap } from "./firmwareSvdInterrupts.js";
import { firmwareVectorTableSchema } from "./firmwareVectorTable.js";
import { parseFirmwareVectorTable } from "./firmwareVectorTableParser.js";

const SAMPLE_SVD = `<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>STM32F405</name>
  <peripherals>
    <peripheral>
      <name>TIM2</name>
      <interrupt><name>TIM2_IRQ</name><value>28</value></interrupt>
    </peripheral>
    <peripheral>
      <name>CAN1</name>
      <interrupt><name>CAN1_SCE</name><value>22</value></interrupt>
    </peripheral>
    <peripheral>
      <name>USB_LP</name>
      <interrupt><name>USB_LP_CAN1_RX0</name><value>20</value></interrupt>
    </peripheral>
    <peripheral>
      <name>CAN1_DUP</name>
      <interrupt><name>CAN1_RX0_ALIAS</name><value>20</value></interrupt>
    </peripheral>
  </peripherals>
</device>`;

describe("parseFirmwareVectorTable ARM M-profile", () => {
  it("decodes ARMv8-M exceptions, Thumb bit-0 violations, shared stubs, and CMSIS-SVD IRQs", () => {
    const svd = parseSvdInterruptMap(SAMPLE_SVD);
    expect(svd.ok).toBe(true);
    if (!svd.ok) return;

    // 48 slots = 16 system + 32 external IRQs (IRQ 0..31)
    const buf = Buffer.alloc(48 * 4, 0);
    buf.writeUInt32LE(0x20020000, 0); // InitialSP
    buf.writeUInt32LE(0x08000201, 4); // Reset (Thumb)
    buf.writeUInt32LE(0x08000301, 8); // NMI -> Default_Handler
    buf.writeUInt32LE(0x08000301, 12); // HardFault -> Default_Handler
    buf.writeUInt32LE(0x08000401, 28); // Slot 7 = SecureFault on armv8-m
    buf.writeUInt32LE(0xdeadbeef, 32); // Slot 8 = Reserved non-zero anomaly
    buf.writeUInt32LE(0x08000500, 15 * 4); // SysTick even address (Thumb bit 0 clear!)
    buf.writeUInt32LE(0x08000601, (16 + 28) * 4); // IRQ 28 -> TIM2_IRQ
    buf.writeUInt32LE(0x08000701, (16 + 20) * 4); // IRQ 20 -> ambiguous in SVD
    buf.writeUInt32LE(0x08000301, (16 + 5) * 4); // IRQ 5 -> unmapped, shares Default_Handler

    const parsed = parseFirmwareVectorTable({
      artifact: {
        path: "/tmp/fw.bin",
        sha256: "a".repeat(64),
        bytes: buf.length,
      },
      architecture: "armv8-m",
      baseAddressHex: "0x08000000",
      vectorTableOffset: 0,
      maxEntries: 64,
      tableBytes: buf,
      svdSupplied: true,
      svdMap: svd.value,
    });

    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const report = parsed.value;
    expect(firmwareVectorTableSchema.safeParse(report).success).toBe(true);
    expect(report.initial_stack_pointer).toBe("0x20020000");
    expect(report.reset_code_address).toBe("0x8000200");
    expect(report.vtor_aligned).toBe(true);

    // Slot 7 on armv8-m is SecureFault
    expect(report.arm_entries[7]).toMatchObject({
      kind: "system_exception",
      name: "SecureFault",
      name_basis: "architecture_manual",
      target_code_address: "0x8000400",
      status: "active",
    });
    // Slot 8 non-zero reserved
    expect(report.arm_entries[8]?.status).toBe("nonzero_reserved");
    // Slot 15 SysTick missing Thumb bit 0
    expect(report.arm_entries[15]).toMatchObject({
      name: "SysTick",
      thumb_bit_set: false,
      status: "invalid_even_thumb_address",
    });
    // IRQ 28 mapped from SVD
    expect(report.arm_entries[16 + 28]).toMatchObject({
      kind: "external_irq",
      irq_number: 28,
      name: "TIM2_IRQ",
      name_basis: "explicit_profile",
      peripheral_name: "TIM2",
      target_code_address: "0x8000600",
    });
    // IRQ 20 ambiguous in SVD -> name stays null, candidates preserved
    expect(report.arm_entries[16 + 20]).toMatchObject({
      irq_number: 20,
      name: null,
      name_basis: "observed_slot",
      ambiguous_profile_names: [
        "USB_LP:USB_LP_CAN1_RX0",
        "CAN1_DUP:CAN1_RX0_ALIAS",
      ],
    });
    expect(report.shared_handler_groups[0]).toEqual({
      target_code_address: "0x8000300",
      slot_count: 3,
      slot_indices: [2, 3, 21],
      likely_default_stub: true,
    });
    expect(report.svd_interrupts).toEqual({
      supplied: true,
      mapped_irq_count: 1,
      ambiguous_irq_count: 1,
      unmapped_active_irq_count: 1,
    });
  });

  it("refuses DOCTYPE in svd_xml and flags unaligned VTOR offsets", () => {
    const doctypeSvd = `<!DOCTYPE device SYSTEM "x.dtd"><device><peripherals/></device>`;
    expect(parseSvdInterruptMap(doctypeSvd).ok).toBe(false);

    const buf = Buffer.alloc(64, 0);
    buf.writeUInt32LE(0x20010000, 0x20);
    buf.writeUInt32LE(0x08000101, 0x24);
    const parsed = parseFirmwareVectorTable({
      artifact: { path: "/tmp/u.bin", sha256: "b".repeat(64), bytes: 64 },
      architecture: "armv7-m",
      baseAddressHex: "0x08000000",
      vectorTableOffset: 0x20,
      maxEntries: 8,
      tableBytes: buf.subarray(0x20),
      svdSupplied: false,
      svdMap: new Map(),
    });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.vtor_aligned).toBe(false);
    expect(
      parsed.value.anomalies.some((a) => a.includes("not 128-byte aligned")),
    ).toBe(true);
  });
});

describe("parseFirmwareVectorTable RISC-V mtvec", () => {
  it("decodes JAL and compressed C.J vectored jump slots and standard cause names", () => {
    const buf = Buffer.alloc(64, 0);
    // JAL x0, +0x200 -> imm=0x200: imm[10:1]=0x100 << 21 = 0x20000000 | 0x6f
    buf.writeUInt32LE(0x2000006f, 0); // slot 0 -> base + 0x200
    buf.writeUInt32LE(0x3000006f, 3 * 4); // slot 3 (MachineSoftwareInterrupt) -> slotAddr + 0x300
    buf.writeUInt32LE(0x4000006f, 7 * 4); // slot 7 (MachineTimerInterrupt) -> slotAddr + 0x400
    // Slot 11 (MachineExternalInterrupt): compressed C.J +0x10 -> b4=1 (bit 11): 0xa801
    buf.writeUInt16LE(0xa801, 11 * 4);

    const parsed = parseFirmwareVectorTable({
      artifact: {
        path: "/tmp/rv.bin",
        sha256: "c".repeat(64),
        bytes: buf.length,
      },
      architecture: "riscv",
      baseAddressHex: "0x80000000",
      vectorTableOffset: 0,
      maxEntries: 16,
      tableBytes: buf,
      svdSupplied: false,
      svdMap: new Map(),
    });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const report = parsed.value;
    expect(firmwareVectorTableSchema.safeParse(report).success).toBe(true);
    expect(report.riscv_table_shape).toBe("vectored_jumps");
    expect(report.reset_code_address).toBe("0x80000200");
    expect(report.riscv_slots[3]).toMatchObject({
      cause_code: 3,
      name: "MachineSoftwareInterrupt",
      name_basis: "architecture_manual",
      encoding: "jal",
      target_code_address: "0x8000030c",
    });
    expect(report.riscv_slots[7]).toMatchObject({
      cause_code: 7,
      name: "MachineTimerInterrupt",
      target_code_address: "0x8000041c",
    });
    expect(report.riscv_slots[11]).toMatchObject({
      cause_code: 11,
      name: "MachineExternalInterrupt",
      encoding: "c_j",
      target_code_address: "0x8000003c",
    });
  });
});
