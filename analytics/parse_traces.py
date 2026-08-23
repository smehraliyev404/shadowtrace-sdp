# ShadowTrace: Distributed trace parser and feature extractor
# Parses OTel JSON spans into Directed Acyclic Graphs (DAGs) and time-weighted latency edges

import os
import glob
import json
import pandas as pd
import networkx as nx

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATA_DIR = os.path.join(SCRIPT_DIR, "..", "data", "raw_traces")

def parse_single_trace_json(json_path):
    # Parses a single OpenTelemetry JSON trace dump file into spans and edge DataFrames
    spans_list = []
    edges_list = []
    
    with open(json_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"[!] Error decoding JSON in {json_path}")
            return pd.DataFrame(), pd.DataFrame()

    # Handle Jaeger API wrapper or raw OTel JSON
    trace_data = data.get("data", [data]) if isinstance(data, dict) and "data" in data else [data]

    for trace_item in trace_data:
        spans = trace_item.get("spans", []) if isinstance(trace_item, dict) else []
        processes = trace_item.get("processes", {}) if isinstance(trace_item, dict) else {}

        span_dict = {}
        for span in spans:
            span_id = span.get("spanID") or span.get("spanId")
            trace_id = span.get("traceID") or span.get("traceId")
            process_id = span.get("processID")
            
            # Resolve service name
            service_name = "unknown_service"
            if process_id and process_id in processes:
                service_name = processes[process_id].get("serviceName", "unknown_service")

            start_time = span.get("startTime", 0) # Microseconds
            duration = span.get("duration", 0)     # Microseconds
            operation_name = span.get("operationName") or span.get("name")
            
            # Attributes keys
            tags = span.get("tags", []) or span.get("attributes", [])
            attr_keys = [t.get("key") for t in tags if isinstance(t, dict)]

            span_record = {
                "trace_id": trace_id,
                "span_id": span_id,
                "service_name": service_name,
                "operation_name": operation_name,
                "start_time": start_time,
                "end_time": start_time + duration,
                "duration_ms": duration / 1000.0,
                "attribute_keys": attr_keys
            }
            spans_list.append(span_record)
            span_dict[span_id] = span_record

        # Build edges (Parent -> Child relationships)
        for span in spans:
            child_id = span.get("spanID") or span.get("spanId")
            references = span.get("references", [])
            for ref in references:
                if ref.get("refType") == "CHILD_OF":
                    parent_id = ref.get("spanID")
                    if parent_id in span_dict and child_id in span_dict:
                        parent_span = span_dict[parent_id]
                        child_span = span_dict[child_id]
                        
                        # Time-weighted edge latency: w_ij = T_start(child) - T_start(parent)
                        edge_latency_ms = (child_span["start_time"] - parent_span["start_time"]) / 1000.0
                        
                        edges_list.append({
                            "trace_id": child_span["trace_id"],
                            "parent_service": parent_span["service_name"],
                            "child_service": child_span["service_name"],
                            "parent_span_id": parent_id,
                            "child_span_id": child_id,
                            "edge_latency_ms": max(0.0, edge_latency_ms)
                        })

    df_spans = pd.DataFrame(spans_list)
    df_edges = pd.DataFrame(edges_list)
    return df_spans, df_edges

def build_networkx_dag(df_spans, df_edges):
    # Converts span and edge DataFrames into a NetworkX Directed Acyclic Graph (DAG)
    G = nx.DiGraph()
    
    if df_spans.empty:
        return G

    for _, row in df_spans.iterrows():
        G.add_node(row["service_name"], duration_ms=row["duration_ms"])

    for _, row in df_edges.iterrows():
        G.add_edge(row["parent_service"], row["child_service"], weight=row["edge_latency_ms"])

    return G

def parse_all_harvested_traces(data_dir=DEFAULT_DATA_DIR):
    # Loads and parses all JSON files inside the data_dir folder
    json_files = glob.glob(os.path.join(data_dir, "*.json"))
    print(f"[*] Target Directory: {os.path.abspath(data_dir)}")
    print(f"[*] Found {len(json_files)} raw trace JSON files.")

    all_spans = []
    all_edges = []

    for file_path in json_files:
        df_s, df_e = parse_single_trace_json(file_path)
        if not df_s.empty:
            all_spans.append(df_s)
        if not df_e.empty:
            all_edges.append(df_e)

    df_all_spans = pd.concat(all_spans, ignore_index=True) if all_spans else pd.DataFrame()
    df_all_edges = pd.concat(all_edges, ignore_index=True) if all_edges else pd.DataFrame()

    print(f"[+] Successfully parsed {len(df_all_spans)} spans and {len(df_all_edges)} edges across all trace DAGs.")
    return df_all_spans, df_all_edges

if __name__ == "__main__":
    df_spans, df_edges = parse_all_harvested_traces()
    
    if not df_spans.empty:
        print(f"Total Unique Services (Nodes): {df_spans['service_name'].nunique()}")
        print(f"Service Node List: {df_spans['service_name'].unique().tolist()}")
        print(f"Average Span Duration: {df_spans['duration_ms'].mean():.2f} ms")
        if not df_edges.empty:
            print(f"Total Call Dependency Edges: {len(df_edges)}")
            print(f"Average Inter-Service Latency (w_ij): {df_edges['edge_latency_ms'].mean():.2f} ms")
        
        print("\nSample Spans:")
        print(df_spans[['trace_id', 'service_name', 'operation_name', 'duration_ms']].head())
        
        if not df_edges.empty:
            print("\nSample Time-Weighted Edges:")
            print(df_edges[['trace_id', 'parent_service', 'child_service', 'edge_latency_ms']].head())
    else:
        print("[!] No trace data found yet. Run harvest_traces.py to populate data/raw_traces/")
