"""
PII Detection & Redaction in CSV Exports
==========================================
Scans CSV files for Personally Identifiable Information (PII), redacts or
pseudonymizes sensitive fields, and produces a GDPR/HIPAA compliance audit trail.

Uses both regex pattern matching (fast, deterministic) AND Claude AI (for
context-aware detection of PII the regex can't catch).

Usage:
    python pii_redactor.py --file data.csv
    python pii_redactor.py --file data.csv --mode pseudonymize
    python pii_redactor.py --file data.csv --ai-scan --mode redact
    python pii_redactor.py --file data.csv --whitelist "product_id,order_id"
"""

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import anthropic
import pandas as pd


# ---------------------------------------------------------------------------
# PII pattern definitions
# ---------------------------------------------------------------------------

@dataclass
class PiiPattern:
    name: str
    category: str       # "identity" | "contact" | "financial" | "health" | "credentials"
    pattern: str
    severity: str       # "high" | "medium" | "low"
    description: str


PII_PATTERNS: list[PiiPattern] = [
    PiiPattern("SSN", "identity",    r"\b\d{3}-\d{2}-\d{4}\b",                                "high",   "US Social Security Number"),
    PiiPattern("SSN_NODASH", "identity", r"\b\d{9}\b",                                        "medium", "Possible SSN without dashes"),
    PiiPattern("EMAIL", "contact",   r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b","high",   "Email address"),
    PiiPattern("PHONE_US", "contact",r"\b(\+1[\s.-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b","high", "US Phone number"),
    PiiPattern("PHONE_INTL","contact",r"\+\d{1,3}[\s\-]?\d{6,14}\b",                          "high",   "International phone number"),
    PiiPattern("CREDIT_CARD","financial",r"\b(?:\d[ -]?){13,16}\b",                            "high",   "Credit/debit card number"),
    PiiPattern("IBAN",      "financial",r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,}(?:[A-Z0-9]{0,3})?\b","high","International bank account number"),
    PiiPattern("IP_V4",     "identity",r"\b(?:\d{1,3}\.){3}\d{1,3}\b",                        "medium", "IPv4 address"),
    PiiPattern("DOB_US",    "identity",r"\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b","medium","Date of birth (MM/DD/YYYY)"),
    PiiPattern("ZIP_US",    "contact", r"\b\d{5}(?:-\d{4})?\b",                                "low",    "US ZIP code"),
    PiiPattern("PASSPORT",  "identity",r"\b[A-Z]{1,2}\d{6,9}\b",                              "high",   "Passport number"),
    PiiPattern("NPI",       "health",  r"\b\d{10}\b",                                         "medium", "Possible NPI (medical provider) number"),
    PiiPattern("API_KEY",   "credentials", r"\b(?:sk|pk|api|key)[-_]?[A-Za-z0-9]{20,}\b",    "high",   "Possible API key or secret"),
]

# Column name heuristics — if a column NAME suggests PII, flag it
PII_COLUMN_HINTS: dict[str, str] = {
    r"(^|_)(ssn|social.?sec)": "SSN",
    r"(^|_)(email|e_mail|e-mail)": "EMAIL",
    r"(^|_)(phone|mobile|cell|tel)": "PHONE",
    r"(^|_)(dob|birth.?date|date.?of.?birth)": "DOB",
    r"(^|_)(name|first.?name|last.?name|full.?name)": "NAME",
    r"(^|_)(address|addr|street|city|zip|postal)": "ADDRESS",
    r"(^|_)(credit|card.?num|cc.?num|pan)": "CREDIT_CARD",
    r"(^|_)(password|passwd|pwd|secret|token)": "CREDENTIALS",
    r"(^|_)(ip.?addr|ip_address|user.?ip)": "IP_ADDRESS",
    r"(^|_)(passport|national.?id|drivers.?lic)": "GOVERNMENT_ID",
    r"(^|_)(salary|income|wage|compensation)": "FINANCIAL",
    r"(^|_)(diagnosis|condition|medication|health)": "HEALTH",
    r"(^|_)(race|ethnicity|religion|political)": "SENSITIVE_ATTR",
}


# ---------------------------------------------------------------------------
# Detection results
# ---------------------------------------------------------------------------

@dataclass
class PiiHit:
    column: str
    row_index: int
    original_value: str
    pii_type: str
    category: str
    severity: str
    detection_method: str   # "regex" | "column_hint" | "ai"


@dataclass
class ColumnPiiSummary:
    column: str
    pii_types: list[str]
    hit_count: int
    severity: str
    detection_methods: list[str]
    recommended_action: str


@dataclass
class AuditReport:
    file_path: str
    timestamp: str
    mode: str
    total_rows: int
    total_columns: int
    pii_columns: list[str]
    column_summaries: list[ColumnPiiSummary]
    total_pii_hits: int
    redacted_values: int
    high_severity_columns: list[str]
    ai_findings: list[str]
    compliance_notes: list[str]


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

def detect_by_regex(df: pd.DataFrame, whitelist: set[str]) -> list[PiiHit]:
    hits: list[PiiHit] = []
    for col in df.columns:
        if col in whitelist:
            continue
        col_str = df[col].dropna().astype(str)
        for pattern_def in PII_PATTERNS:
            rx = re.compile(pattern_def.pattern, re.IGNORECASE)
            matches = col_str[col_str.str.contains(rx, regex=True, na=False)]
            for idx in matches.index:
                hits.append(PiiHit(
                    column=col,
                    row_index=int(idx),
                    original_value=str(df.at[idx, col]),
                    pii_type=pattern_def.name,
                    category=pattern_def.category,
                    severity=pattern_def.severity,
                    detection_method="regex",
                ))
    return hits


def detect_by_column_hints(df: pd.DataFrame, whitelist: set[str]) -> list[PiiHit]:
    hits: list[PiiHit] = []
    for col in df.columns:
        if col in whitelist:
            continue
        col_lower = col.lower()
        for pattern, pii_type in PII_COLUMN_HINTS.items():
            if re.search(pattern, col_lower):
                non_null = df[col].dropna()
                for idx in non_null.index:
                    hits.append(PiiHit(
                        column=col,
                        row_index=int(idx),
                        original_value=str(df.at[idx, col]),
                        pii_type=pii_type,
                        category="inferred",
                        severity="high",
                        detection_method="column_hint",
                    ))
                break
    return hits


def detect_by_ai(client: anthropic.Anthropic, df: pd.DataFrame, whitelist: set[str]) -> list[str]:
    """Ask Claude to review column names + sample values for PII not caught by rules."""
    sample: dict[str, list[str]] = {}
    for col in df.columns:
        if col in whitelist:
            continue
        sample[col] = df[col].dropna().astype(str).head(5).tolist()

    prompt = f"""You are a data privacy expert performing a PII audit.

Review these CSV column names and sample values. Identify any columns likely containing
Personally Identifiable Information (PII) that may not be obvious from the column name alone.
Focus on: names, locations, identifiers, free-text fields containing personal info, encoded data.

Columns and samples:
{json.dumps(sample, indent=2)}

Respond ONLY with a JSON array of findings, each with:
{{"column": "col_name", "pii_type": "type", "reasoning": "brief explanation", "severity": "high|medium|low"}}

If no additional PII is found beyond obvious column names, return an empty array []."""

    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=800,
        messages=[{"role": "user", "content": prompt}]
    )

    raw = message.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    try:
        findings = json.loads(raw)
        return [f"[AI] {f['column']}: {f['pii_type']} — {f['reasoning']} (severity: {f['severity']})"
                for f in findings if isinstance(f, dict)]
    except Exception:
        return [f"[AI raw output] {raw[:300]}"]


# ---------------------------------------------------------------------------
# Redaction / pseudonymization
# ---------------------------------------------------------------------------

def redact_value(value: str, pii_type: str, mode: str) -> str:
    if mode == "redact":
        return f"[REDACTED:{pii_type}]"
    elif mode == "pseudonymize":
        hashed = hashlib.sha256(value.encode()).hexdigest()[:12]
        return f"PSEUDO_{pii_type}_{hashed}"
    elif mode == "mask":
        if len(value) <= 4:
            return "*" * len(value)
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
    return value


def apply_redactions(df: pd.DataFrame, hits: list[PiiHit], mode: str) -> tuple[pd.DataFrame, int]:
    redacted_df = df.copy()
    count = 0
    cell_map: dict[tuple[int, str], str] = {}
    sev_order = {"high": 3, "medium": 2, "low": 1}
    for hit in hits:
        key = (hit.row_index, hit.column)
        if key not in cell_map or sev_order.get(hit.severity, 0) > sev_order.get("low", 0):
            cell_map[key] = hit.pii_type

    for (row_idx, col), pii_type in cell_map.items():
        original = str(redacted_df.at[row_idx, col])
        redacted_df.at[row_idx, col] = redact_value(original, pii_type, mode)
        count += 1

    return redacted_df, count


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def build_audit_report(
    file_path: str, mode: str, df: pd.DataFrame,
    hits: list[PiiHit], redacted_count: int, ai_findings: list[str]
) -> AuditReport:
    from collections import defaultdict

    col_hits: dict[str, list[PiiHit]] = defaultdict(list)
    for h in hits:
        col_hits[h.column].append(h)

    summaries: list[ColumnPiiSummary] = []
    for col, col_hit_list in col_hits.items():
        types = list({h.pii_type for h in col_hit_list})
        methods = list({h.detection_method for h in col_hit_list})
        max_sev = "low"
        for h in col_hit_list:
            if h.severity == "high":
                max_sev = "high"; break
            elif h.severity == "medium":
                max_sev = "medium"

        if max_sev == "high":
            action = f"{mode.capitalize()} all values in this column before sharing."
        elif max_sev == "medium":
            action = "Review and consider redaction depending on use case."
        else:
            action = "Low risk — document in data inventory."

        summaries.append(ColumnPiiSummary(
            column=col, pii_types=types,
            hit_count=len(col_hit_list),
            severity=max_sev,
            detection_methods=methods,
            recommended_action=action,
        ))

    compliance_notes = [
        "GDPR Art. 5: Personal data should be processed with appropriate security.",
        "Ensure a Data Processing Agreement is in place before sharing this file.",
        f"Audit trail generated at {datetime.now().isoformat()} — retain for 3 years.",
        "Consider data minimization: only share columns necessary for the intended purpose.",
    ]
    if any(s.severity == "high" for s in summaries):
        compliance_notes.insert(0, "⚠️  HIGH SEVERITY PII detected — review sharing permissions immediately.")

    return AuditReport(
        file_path=file_path,
        timestamp=datetime.now().isoformat(),
        mode=mode,
        total_rows=len(df),
        total_columns=len(df.columns),
        pii_columns=list(col_hits.keys()),
        column_summaries=summaries,
        total_pii_hits=len(hits),
        redacted_values=redacted_count,
        high_severity_columns=[s.column for s in summaries if s.severity == "high"],
        ai_findings=ai_findings,
        compliance_notes=compliance_notes,
    )


def print_audit_report(report: AuditReport) -> None:
    print(f"\n{'='*65}")
    print(f"  PII AUDIT REPORT")
    print(f"{'='*65}")
    print(f"  File      : {report.file_path}")
    print(f"  Timestamp : {report.timestamp}")
    print(f"  Mode      : {report.mode.upper()}")
    print(f"  Rows      : {report.total_rows:,}  |  Columns: {report.total_columns}")
    print(f"  PII Hits  : {report.total_pii_hits}  |  Redacted: {report.redacted_values}")
    print(f"{'='*65}\n")

    if report.high_severity_columns:
        print("  ⚠️  HIGH SEVERITY COLUMNS:")
        for col in report.high_severity_columns:
            print(f"     🔴 {col}")
        print()

    print("  COLUMN ANALYSIS:")
    for s in sorted(report.column_summaries, key=lambda x: {"high":0,"medium":1,"low":2}.get(x.severity, 3)):
        icon = "🔴" if s.severity == "high" else "🟡" if s.severity == "medium" else "🟢"
        methods = "+".join(s.detection_methods)
        print(f"  {icon} {s.column} ({s.hit_count} hits) — {', '.join(s.pii_types)} [{methods}]")
        print(f"     → {s.recommended_action}")
    print()

    if report.ai_findings:
        print("  AI FINDINGS:")
        for finding in report.ai_findings:
            print(f"  🤖 {finding}")
        print()

    print("  COMPLIANCE NOTES:")
    for note in report.compliance_notes:
        print(f"  📋 {note}")
    print()


def save_audit(report: AuditReport, path: str) -> None:
    data = asdict(report)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  📄 Audit trail saved to: {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="PII Detection & Redaction for CSV Files")
    parser.add_argument("--file", required=True, help="Input CSV file path")
    parser.add_argument("--mode", choices=["redact", "pseudonymize", "mask", "report-only"],
                        default="redact", help="Redaction mode (default: redact)")
    parser.add_argument("--ai-scan", action="store_true", help="Use Claude AI for additional PII detection")
    parser.add_argument("--whitelist", default="", help="Comma-separated column names to skip")
    parser.add_argument("--output", default="", help="Output CSV path for redacted file")
    parser.add_argument("--audit-output", default="", help="Output JSON path for audit trail")
    parser.add_argument("--no-column-hints", action="store_true", help="Disable column name heuristics")
    args = parser.parse_args()

    print(f"\n📂 Loading: {args.file}")
    try:
        df = pd.read_csv(args.file)
    except Exception as e:
        print(f"❌ Failed to read CSV: {e}")
        sys.exit(1)
    print(f"   {len(df):,} rows × {len(df.columns)} columns loaded.")

    whitelist = {c.strip() for c in args.whitelist.split(",") if c.strip()}
    if whitelist:
        print(f"   Whitelisting columns: {', '.join(whitelist)}")

    print("\n🔍 Running regex PII detection...")
    hits = detect_by_regex(df, whitelist)
    print(f"   {len(hits)} regex hits across {len({h.column for h in hits})} column(s).")

    if not args.no_column_hints:
        print("🏷️  Running column name heuristics...")
        hint_hits = detect_by_column_hints(df, whitelist)
        existing_cols = {h.column for h in hits}
        new_hint_hits = [h for h in hint_hits if h.column not in existing_cols]
        hits.extend(new_hint_hits)
        if new_hint_hits:
            print(f"   {len(new_hint_hits)} additional hits from column name hints.")

    ai_findings: list[str] = []
    if args.ai_scan:
        print("🤖 Running AI PII scan...")
        client = anthropic.Anthropic()
        ai_findings = detect_by_ai(client, df, whitelist)
        print(f"   {len(ai_findings)} AI finding(s).")

    redacted_count = 0
    redacted_df = df

    if args.mode != "report-only" and hits:
        print(f"\n✂️  Applying {args.mode} to {len({(h.row_index, h.column) for h in hits})} cells...")
        redacted_df, redacted_count = apply_redactions(df, hits, args.mode)

    report = build_audit_report(args.file, args.mode, df, hits, redacted_count, ai_findings)
    print_audit_report(report)

    if args.mode != "report-only":
        out_csv = args.output or args.file.replace(".csv", f"_{args.mode}d.csv")
        redacted_df.to_csv(out_csv, index=False)
        print(f"  ✅ Redacted CSV saved to: {out_csv}")

    audit_path = args.audit_output or args.file.replace(".csv", "_pii_audit.json")
    save_audit(report, audit_path)


if __name__ == "__main__":
    main()
