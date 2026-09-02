# ShadowTrace: Privacy leakage and Shannon Entropy audit
# Quantifying PII and secret leakage in raw OpenTelemetry traces (spans and process metadata)

import os
import glob
import json
import math
import re
from collections import Counter
import pandas as pd
import matplotlib.pyplot as plt

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DEFAULT_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "raw_traces")
CHART_OUTPUT_PATH = os.path.join(PROJECT_ROOT, "docs", "diagrams", "privacy_leakage_chart.png")

def calculate_shannon_entropy(text_string: str) -> float:
    # Calculating Shannon Entropy: H(X) = - sum(P(x_i) * log2(P(x_i)))
    if not text_string or not isinstance(text_string, str):
        return 0.0
    length = len(text_string)
    counts = Counter(text_string)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 4)

REGEX_PATTERNS = {
    "Email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "JWT_Token": r'eyJh[a-zA-Z0-9_-]+\.eyJh[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
    "Credit_Card": r'\b(?:\d[ -]*?){13,16}\b',
    "IPv4_Address": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
}

def detect_regex_pii(text_string: str) -> list:
    if not isinstance(text_string, str):
        return []
    return [pii_type for pii_type, pattern in REGEX_PATTERNS.items() if re.search(pattern, text_string)]

def audit_single_trace(file_path: str, entropy_threshold: float = 3.5) -> list:
    records = []
    if not os.path.exists(file_path):
        return records

    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except Exception:
            return records

    # Support both Jaeger trace format and raw OTel format
    trace_data = data.get("data", [data]) if isinstance(data, dict) and "data" in data else [data]

    for item in trace_data:
        trace_id = item.get("traceID") or item.get("traceId", "")
        spans = item.get("spans", [])
        processes = item.get("processes", {})

        # Process level audit
        for process_id, proc in processes.items():
            service_name = proc.get("serviceName", "unknown_service")
            proc_tags = proc.get("tags", [])
            for tag in proc_tags:
                key = tag.get("key", "")
                val = tag.get("value", "")
                val_str = str(val.get("stringValue", val) if isinstance(val, dict) else val)

                entropy = calculate_shannon_entropy(val_str)
                pii_flags = detect_regex_pii(val_str)
                is_high_entropy = entropy >= entropy_threshold

                if is_high_entropy or len(pii_flags) > 0:
                    records.append({
                        "trace_id": trace_id,
                        "span_id": "(process-level)",
                        "service_name": service_name,
                        "span_name": "(process metadata)",
                        "attribute_key": key,
                        "attribute_value_sample": val_str[:30] + "..." if len(val_str) > 30 else val_str,
                        "entropy": entropy,
                        "pii_detected": ", ".join(pii_flags) if pii_flags else "None",
                        "requires_redaction": True
                    })

        # Span level audit
        for span in spans:
            span_id = span.get("spanID") or span.get("spanId", "")
            span_name = span.get("operationName") or span.get("name", "")
            process_id = span.get("processID")
            
            service_name = "unknown_service"
            if process_id and process_id in processes:
                service_name = processes[process_id].get("serviceName", "unknown_service")

            # Jaeger uses tags, OTel uses attributes
            tags = span.get("tags", []) or span.get("attributes", [])
            for tag in tags:
                key = tag.get("key", "")
                val = tag.get("value", "")
                # Handle nested OTel stringValue or direct values
                val_str = str(val.get("stringValue", val) if isinstance(val, dict) else val)

                entropy = calculate_shannon_entropy(val_str)
                pii_flags = detect_regex_pii(val_str)
                is_high_entropy = entropy >= entropy_threshold

                if is_high_entropy or len(pii_flags) > 0:
                    records.append({
                        "trace_id": trace_id,
                        "span_id": span_id,
                        "service_name": service_name,
                        "span_name": span_name,
                        "attribute_key": key,
                        "attribute_value_sample": val_str[:30] + "..." if len(val_str) > 30 else val_str,
                        "entropy": entropy,
                        "pii_detected": ", ".join(pii_flags) if pii_flags else "None",
                        "requires_redaction": True
                    })

    return records

def audit_all_traces(data_dir=DEFAULT_DATA_DIR, entropy_threshold=3.5):
    json_files = glob.glob(os.path.join(data_dir, "*.json"))
    print(f"[*] Auditing {len(json_files)} raw trace JSON files in '{os.path.abspath(data_dir)}'...")

    all_records = []
    for file_path in json_files:
        records = audit_single_trace(file_path, entropy_threshold)
        all_records.extend(records)

    return pd.DataFrame(all_records)

if __name__ == "__main__":
    print("ShadowTrace privacy audit script started")
    df_audit = audit_all_traces()

    print(f"Total High-Entropy / Sensitive Attributes Flagged: {len(df_audit)}")

    if not df_audit.empty:
        print(f"Services with Leaks: {df_audit['service_name'].unique().tolist()}")
        print("\nSample Leaked / High-Entropy Attributes:")
        print(df_audit[['service_name', 'attribute_key', 'entropy', 'pii_detected', 'attribute_value_sample']].head(10))

        # Plot and save chart
        os.makedirs(os.path.dirname(CHART_OUTPUT_PATH), exist_ok=True)
        plt.figure(figsize=(10, 5))
        service_counts = df_audit['service_name'].value_counts()

        ax = service_counts.plot(kind='bar', color='#e63946', edgecolor='black', alpha=0.9)
        plt.title('ShadowTrace: Privacy Leakage per Microservice (Shannon Entropy >= 3.5 & PII)', fontsize=12, fontweight='bold')
        plt.xlabel('Microservice Node', fontsize=10, fontweight='bold')
        plt.ylabel('Flagged Sensitive Attributes Count', fontsize=10, fontweight='bold')
        plt.xticks(rotation=30, ha='right')
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        for p in ax.patches:
            ax.annotate(str(int(p.get_height())), (p.get_x() + p.get_width() / 2., p.get_height()),
                        ha='center', va='bottom', fontsize=9, xytext=(0, 3), textcoords='offset points')

        plt.tight_layout()
        plt.savefig(CHART_OUTPUT_PATH, dpi=300)
        print(f"\n[✓] Privacy chart saved successfully to: {CHART_OUTPUT_PATH}")
    else:
        print("[!] No leaky attributes found. Ensure data/raw_traces has trace JSON files.")
