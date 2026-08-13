<!-- Generated from ../workspace.dsl by make architecture. Do not edit. -->

```mermaid
graph LR
  linkStyle default fill:#ffffff

  subgraph diagram ["Deployment View: Clustered"]
    style diagram fill:#ffffff,stroke:#ffffff

    subgraph 75 ["OpenClaw host"]
      style 75 fill:#ffffff,stroke:#444444,color:#444444

      76["<div style='font-weight: bold'>OpenClaw (Hindsight plugin)</div><div style='font-size: 70%; margin-top: 0px'>[Software System]</div><div style='font-size: 80%; margin-top:10px'>Current supported client<br />integration.</div>"]
      style 76 fill:#ffffff,stroke:#444444,color:#444444
    end

    subgraph 77 ["Memory Router cluster"]
      style 77 fill:#ffffff,stroke:#444444,color:#444444

      78["<div style='font-weight: bold'>External shared admin rate limiter</div><div style='font-size: 70%; margin-top: 0px'>[Infrastructure Node: Reverse proxy / shared limiter]</div><div style='font-size: 80%; margin-top:10px'>Required in clustered mode<br />for /admin/* before requests<br />reach a replica.</div>"]
      style 78 fill:#ffffff,stroke:#444444,color:#444444
      79["<div style='font-weight: bold'>Memory Router API</div><div style='font-size: 70%; margin-top: 0px'>[Container: Python 3.12 / FastAPI / Uvicorn]</div><div style='font-size: 80%; margin-top:10px'>Hindsight-compatible HTTP<br />facade, routing, policy,<br />security, quarantine, and<br />review API.</div>"]
      style 79 fill:#ffffff,stroke:#444444,color:#444444
      81["<div style='font-weight: bold'>Memory Router API</div><div style='font-size: 70%; margin-top: 0px'>[Container: Python 3.12 / FastAPI / Uvicorn]</div><div style='font-size: 80%; margin-top:10px'>Hindsight-compatible HTTP<br />facade, routing, policy,<br />security, quarantine, and<br />review API.</div>"]
      style 81 fill:#ffffff,stroke:#444444,color:#444444
    end

    subgraph 85 ["PostgreSQL"]
      style 85 fill:#ffffff,stroke:#444444,color:#444444

      86[("<div style='font-weight: bold'>Quarantine Storage</div><div style='font-size: 70%; margin-top: 0px'>[Container: SQLite (single-node) or PostgreSQL (clustered)]</div><div style='font-size: 80%; margin-top:10px'>Encrypted quarantine/review<br />state, audit history, and<br />shared rate-limit state when<br />PostgreSQL is used.</div>")]
      style 86 fill:#ffffff,stroke:#444444,color:#444444
    end

    subgraph 89 ["Hindsight host"]
      style 89 fill:#ffffff,stroke:#444444,color:#444444

      90["<div style='font-weight: bold'>Hindsight</div><div style='font-size: 70%; margin-top: 0px'>[Software System]</div><div style='font-size: 80%; margin-top:10px'>Only implemented memory<br />backend.</div>"]
      style 90 fill:#ffffff,stroke:#444444,color:#444444
    end

    subgraph 93 ["Reviewer workstation"]
      style 93 fill:#ffffff,stroke:#444444,color:#444444

      94["<div style='font-weight: bold'>Offline Review Tooling</div><div style='font-size: 70%; margin-top: 0px'>[Container: Python CLI]</div><div style='font-size: 80%; margin-top:10px'>Decrypts exported quarantine<br />envelopes outside the router<br />process. The private key is<br />supplied locally and is never<br />available to Memory Router.</div>"]
      style 94 fill:#ffffff,stroke:#444444,color:#444444
    end

    76-. "<div>Uses Hindsight-compatible API</div><div style='font-size: 70%'>[HTTP/JSON + Bearer]</div>" .->79
    76-. "<div>Uses Hindsight-compatible API</div><div style='font-size: 70%'>[HTTP/JSON + Bearer]</div>" .->81
    78-. "<div>Forwards rate-limited<br />/admin/* traffic</div><div style='font-size: 70%'>[HTTP]</div>" .->79
    78-. "<div>Forwards rate-limited<br />/admin/* traffic</div><div style='font-size: 70%'>[HTTP]</div>" .->81
    79-. "<div>Persists quarantine/review<br />state and, in PostgreSQL<br />mode, shared rate-limit state</div><div style='font-size: 70%'>[SQL]</div>" .->86
    81-. "<div>Persists quarantine/review<br />state and, in PostgreSQL<br />mode, shared rate-limit state</div><div style='font-size: 70%'>[SQL]</div>" .->86
    79-. "<div>Calls supported Hindsight<br />endpoints</div><div style='font-size: 70%'>[HTTP/JSON]</div>" .->90
    81-. "<div>Calls supported Hindsight<br />endpoints</div><div style='font-size: 70%'>[HTTP/JSON]</div>" .->90

  end
```
