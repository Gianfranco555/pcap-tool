# Handling NaN Values in Integer Fields

This document describes strategies for avoiding the
`TypeError: cannot convert float NaN to integer`
when processing `PcapRecord` data with pandas. The
examples reference existing classes in the repository and
show where defensive conversion can be applied.

## A. Safe Integer Conversion Pre-computation

When building a `packet_df` from `PcapRecord` objects,
fields such as `source_port`, `destination_port`,
`packet_length`, `frame_number`, `tcp_sequence_number`,
`icmp_type` and `icmp_code` may be `None`. After
DataFrame creation they become `NaN` (a float). Use
`fillna()` before converting to integers so downstream
code does not attempt `int(NaN)`.

```python
records = [PcapRecord(...), ...]
packet_df = pd.DataFrame([asdict(r) for r in records])
# Replace missing integers with placeholder 0 (or -1)
int_cols = [
    "source_port",
    "destination_port",
    "packet_length",
    "frame_number",
    "tcp_sequence_number",
    "icmp_type",
    "icmp_code",
]
packet_df[int_cols] = packet_df[int_cols].fillna(0).astype("int64")
```

Choosing the placeholder depends on context. Using `0`
keeps the column integral and ensures code receiving the
DataFrame will not encounter `NaN` values.

## B. Handling `NaN` before `.astype(int)`

If an existing DataFrame column contains `NaN` and must be
integer-typed, use `fillna` with an appropriate sentinel
value prior to conversion.

```python
df["my_int_column"] = df["my_int_column"].fillna(-1).astype("int64")
```

This converts all missing entries to `-1` and casts the
column to integer. Without the `fillna`, pandas would raise
`IntCastingNaNError`.

## C. Class-Specific Considerations

**StatsCollector**

The `add()` method converts `record.destination_port` to
`int` when recording port usage. If a `PcapRecord` instance
contains `None` for the destination port, ensure a default
value is substituted before calling `int()`.

```python
# Within StatsCollector.add
if dest_port is not None and dest_port == dest_port:
    port_key = f"{key}_{int(dest_port)}"
    self.port_counts[port_key] += 1
```

If a caller might supply records where `dest_port` is
`None`, add a guard or replace `None` with `0` before
conversion.

**FlowTable**

`FlowTable._get_key()` and `FlowTable.add_packet()` cast
port numbers and packet length to `int` with default `0`.
If upstream code fails to sanitize these fields, `NaN`
would propagate into `int()` calls. Ensuring that
`packet_df` already has integer placeholders avoids this
issue.

**MetricsBuilder**

When building the final JSON, ports from `tagged_flow_df`
are used to guess services. A `NaN` value would cause
`int(port)` to fail. Use `pd.notna` to verify validity
before conversion, as shown below.

```python
port = row.get("destination_port")
service = guess_service(
    protocol,
    int(port) if pd.notna(port) else None,
    sni=sni if pd.notna(sni) else None,
    http_host=http_host if pd.notna(http_host) else None,
    rdns=rdns,
    is_quic=is_quic,
)
```

This check is already performed in the repository; ensure
similar safeguards are applied wherever integer fields are
read from DataFrames.

## D. Debugging Strategy

To locate the exact source of a `cannot convert float NaN
to integer` error:

1. **Inspect DataFrames** – Print `df.dtypes` and check for
   columns with `float64` where integers are expected.
2. **Use `pd.isna()`** – Insert temporary assertions or
   logging to identify unexpected `NaN` values.
3. **Wrap Conversions** – Surround calls to `int()` or
   `.astype(int)` with try/except blocks during debugging to
   capture the offending value and traceback.
4. **Add Unit Tests** – Create test cases with `None` or
   `NaN` in critical fields to ensure conversions are
   handled gracefully.

These steps make it easier to isolate the line triggering
the exception and to confirm the fix once applied.
