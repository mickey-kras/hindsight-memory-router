<!-- Generated from ../workspace.dsl by make architecture. Do not edit. -->

```mermaid
graph LR
  linkStyle default fill:#ffffff

  subgraph diagram ["System Context View: Memory Router"]
    style diagram fill:#ffffff,stroke:#ffffff

    1["<div style='font-weight: bold'>Operator / Reviewer</div><div style='font-size: 70%; margin-top: 0px'>[Person]</div><div style='font-size: 80%; margin-top:10px'>Reviews quarantined evidence<br />and submits review decisions.</div>"]
    style 1 fill:#ffffff,stroke:#444444,color:#444444
    2["<div style='font-weight: bold'>OpenClaw (Hindsight plugin)</div><div style='font-size: 70%; margin-top: 0px'>[Software System]</div><div style='font-size: 80%; margin-top:10px'>Current supported client<br />integration.</div>"]
    style 2 fill:#ffffff,stroke:#444444,color:#444444
    3["<div style='font-weight: bold'>Hindsight</div><div style='font-size: 70%; margin-top: 0px'>[Software System]</div><div style='font-size: 80%; margin-top:10px'>Only implemented memory<br />backend.</div>"]
    style 3 fill:#ffffff,stroke:#444444,color:#444444
    4["<div style='font-weight: bold'>Memory Router</div><div style='font-size: 70%; margin-top: 0px'>[Software System]</div><div style='font-size: 80%; margin-top:10px'>Policy and security boundary<br />between the OpenClaw<br />Hindsight plugin and<br />Hindsight.</div>"]
    style 4 fill:#ffffff,stroke:#444444,color:#444444

    2-. "<div>Uses Hindsight-compatible API</div><div style='font-size: 70%'>[HTTP/JSON + Bearer]</div>" .->4
    4-. "<div>Calls supported Hindsight<br />endpoints</div><div style='font-size: 70%'>[HTTP/JSON]</div>" .->3
    1-. "<div>Uses quarantine review API</div><div style='font-size: 70%'>[Admin HTTP/JSON + scoped Bearer]</div>" .->4

  end
```
