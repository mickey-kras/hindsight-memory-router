<!-- Generated from ../workspace.dsl by make architecture. Do not edit. -->

```mermaid
sequenceDiagram

  participant 2 as OpenClaw (Hindsight plugin)<br />[Software System]
  participant 7 as HTTP/API Entry & Auth<br />[Component]
  participant 12 as Request/Response Limits & Rate Limiting<br />[Component]
  participant 10 as Policy Orchestration<br />[Component]
  participant 9 as Writer Registry / Bank Routing<br />[Component]
  participant 11 as Security Scanning<br />[Component]
  participant 14 as Quarantine Admission / Storage<br />[Component]
  participant 13 as Hindsight Gateway<br />[Component]
  participant 3 as Hindsight<br />[Software System]

  2->>7: POST memory retain request<br />[HTTP/JSON + Bearer]
  7->>12: Bound body, strict JSON/schema, retain limits
  7->>10: Dispatch validated retain
  10->>9: Resolve writer and write bank
  10->>11: Scan all request strings/keys
  10->>14: If writer is unknown or scan is unsafe: encrypt and queue; stop
  10->>12: If allowed: consume Hindsight retain budget
  10->>13: Retain to assigned Hindsight write bank
  13->>3: POST retain<br />[HTTP/JSON]
```
