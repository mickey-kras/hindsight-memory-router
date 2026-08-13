<!-- Generated from ../workspace.dsl by make architecture. Do not edit. -->

```mermaid
graph LR
  linkStyle default fill:#ffffff

  subgraph diagram ["Deployment View: Single Node"]
    style diagram fill:#ffffff,stroke:#ffffff

    subgraph 62 ["OpenClaw host"]
      style 62 fill:#ffffff,stroke:#444444,color:#444444

      63["<div style='font-weight: bold'>OpenClaw (Hindsight plugin)</div><div style='font-size: 70%; margin-top: 0px'>[Software System]</div><div style='font-size: 80%; margin-top:10px'>Current supported client<br />integration.</div>"]
      style 63 fill:#ffffff,stroke:#444444,color:#444444
    end

    subgraph 64 ["Memory Router host"]
      style 64 fill:#ffffff,stroke:#444444,color:#444444

      65["<div style='font-weight: bold'>Memory Router API</div><div style='font-size: 70%; margin-top: 0px'>[Container: Python 3.12 / FastAPI / Uvicorn]</div><div style='font-size: 80%; margin-top:10px'>Hindsight-compatible HTTP<br />facade, routing, policy,<br />security, quarantine, and<br />review API.</div>"]
      style 65 fill:#ffffff,stroke:#444444,color:#444444
      subgraph 67 ["Local data volume"]
        style 67 fill:#ffffff,stroke:#444444,color:#444444

        68[("<div style='font-weight: bold'>Quarantine Storage</div><div style='font-size: 70%; margin-top: 0px'>[Container: SQLite (single-node) or PostgreSQL (clustered)]</div><div style='font-size: 80%; margin-top:10px'>Encrypted quarantine/review<br />state, audit history, and<br />shared rate-limit state when<br />PostgreSQL is used.</div>")]
        style 68 fill:#ffffff,stroke:#444444,color:#444444
      end

    end

    subgraph 70 ["Hindsight host"]
      style 70 fill:#ffffff,stroke:#444444,color:#444444

      71["<div style='font-weight: bold'>Hindsight</div><div style='font-size: 70%; margin-top: 0px'>[Software System]</div><div style='font-size: 80%; margin-top:10px'>Only implemented memory<br />backend.</div>"]
      style 71 fill:#ffffff,stroke:#444444,color:#444444
    end

    subgraph 73 ["Reviewer workstation"]
      style 73 fill:#ffffff,stroke:#444444,color:#444444

      74["<div style='font-weight: bold'>Offline Review Tooling</div><div style='font-size: 70%; margin-top: 0px'>[Container: Python CLI]</div><div style='font-size: 80%; margin-top:10px'>Decrypts exported quarantine<br />envelopes outside the router<br />process. The private key is<br />supplied locally and is never<br />available to Memory Router.</div>"]
      style 74 fill:#ffffff,stroke:#444444,color:#444444
    end

    63-. "<div>Uses Hindsight-compatible API</div><div style='font-size: 70%'>[HTTP/JSON + Bearer]</div>" .->65
    65-. "<div>Persists quarantine/review<br />state and, in PostgreSQL<br />mode, shared rate-limit state</div><div style='font-size: 70%'>[SQL]</div>" .->68
    65-. "<div>Calls supported Hindsight<br />endpoints</div><div style='font-size: 70%'>[HTTP/JSON]</div>" .->71

  end
```
