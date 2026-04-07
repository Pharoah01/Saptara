"""
Prometheus metrics shared across all SAPTARA services
"""

from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, REGISTRY

# --- Scan / test counters ---
scans_total = Counter(
    "saptara_scans_total",
    "Total number of scans started",
    ["service"],
)

tests_total = Counter(
    "saptara_tests_total",
    "Total number of individual tests executed",
    ["service", "category", "status"],
)

vulnerabilities_found = Counter(
    "saptara_vulnerabilities_found_total",
    "Total vulnerabilities detected",
    ["service", "severity"],
)

# --- Latency ---
scan_duration_seconds = Histogram(
    "saptara_scan_duration_seconds",
    "Time taken to complete a full scan",
    ["service"],
    buckets=[1, 5, 15, 30, 60, 120, 300],
)

http_request_duration_seconds = Histogram(
    "saptara_http_request_duration_seconds",
    "Outbound HTTP request latency during testing",
    ["service", "method"],
    buckets=[0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
)

# --- Active scans gauge ---
active_scans = Gauge(
    "saptara_active_scans",
    "Number of scans currently running",
    ["service"],
)
