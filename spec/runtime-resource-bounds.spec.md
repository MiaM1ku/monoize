# Runtime Resource Bounds Specification

## 0. Status

- **Purpose:** Bound process-local maps and buffers that accept attacker-influenced identities or payloads.
- **Scope:** Applies to `src/bounded_response.rs` and the resource-bound APIs referenced by the database, capture, WebSocket, provider-discovery, and image-transform specifications.

## 1. Configuration parsing

RRB-C1. Each resource-bound environment value in this specification and the linked subsystem specifications MUST accept only positive base-10 integers. Parsers MUST ignore leading and trailing ASCII whitespace around the value. Missing, zero, invalid, or overflowing values MUST use the documented default.

RRB-C2. All limits are process-local. This version requires no multi-instance cache coherence or distributed quota coordination.

## 2. Upstream discovery response bodies

RRB-UD1. `MONOIZE_UPSTREAM_DISCOVERY_MAX_BYTES` MUST select the maximum response-body byte length yielded by the HTTP client for every upstream provider-model discovery and model-metadata discovery request. Its default MUST be `16777216`. Parsing MUST follow RRB-C1.

RRB-UD2. Before reading a discovery response body, Monoize MUST compare a valid HTTP `Content-Length` value with the selected limit. If `Content-Length` exceeds the limit, Monoize MUST reject the response without reading a body chunk.

RRB-UD3. Monoize MUST read a chunked response or a response without `Content-Length` incrementally. Before appending each chunk, Monoize MUST reject the response if the accumulated byte length plus that chunk would exceed the selected limit. Monoize MUST stop polling the body after this rejection.

RRB-UD4. A response whose yielded body length equals the selected limit MUST be accepted. Empty response bodies MUST be accepted by the byte reader.

RRB-UD5. Discovery code MUST parse JSON or construct error text only from bytes returned by the bounded response reader. Discovery code MUST NOT call `reqwest::Response::json`, `reqwest::Response::text`, or `reqwest::Response::bytes` directly.

RRB-UD6. A body rejected by RRB-UD2 or RRB-UD3 MUST produce an error whose message states the configured byte limit. Dashboard provider-model discovery MUST return HTTP `502` with code `upstream_discovery_response_too_large`. A body transport failure within the limit MUST return the subsystem's existing upstream-fetch error.
