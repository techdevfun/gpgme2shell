/**
 * Output helpers: human tables and --json shapes.
 * Every output carries the scope footer.
 */
import type { VerdictResult } from "./verdict.js";

export const SCOPE_FOOTER =
  "Exposure conditions only. This tool does not prove exploitability and never sends a crafted key. " +
  "A SAFE verdict means these three conditions do not line up - not that the host is safe from every GPGME flaw.";

export function verdictLine(r: VerdictResult): string {
  return `verdict: ${r.verdict} (version ${r.version}, linkage ${r.linkage}, exposure ${r.exposure})`;
}

export function conditionLines(r: VerdictResult): string[] {
  const lines: string[] = [];
  for (const c of r.conditions) lines.push(`  - ${c}`);
  lines.push(`  deciding: ${r.deciding}`);
  return lines;
}

export function summaryLine(
  counts: Record<string, number>,
  total: number,
): string {
  const parts = ["EXPOSED", "AT-RISK", "SAFE", "UNKNOWN"].map(
    (v) => `${v} ${counts[v] ?? 0}`,
  );
  return `summary: ${parts.join(", ")} - ${total} install(s) checked`;
}
