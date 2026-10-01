workspace "Hindsight Memory Router" "As-built architecture" {
    model {
        operator = person "Operator / Reviewer" "Reviews quarantined evidence and submits review decisions."

        agents = softwareSystem "Agent Clients" "OpenClaw, coding-agent harnesses, and MCP clients."
        integrations = softwareSystem "Memory Router Integrations" "Trusted agent identity, explicit bank mapping, and authenticated HTTPS transport." {
            bridge = container "Agent Integrations / MCP" "OpenClaw plugin, coding-agent adapters, and stdio MCP server. Shared read coordination and retain replay where configured." "TypeScript / Node.js"
            retainQueue = container "Local Retain Queue" "Bounded plaintext transcript backlog for transient failures; OS locks, FIFO replay, and current write-bank checks." "Local filesystem" "Database"
        }
        hostProxy = softwareSystem "Authenticated Host Proxy (optional)" "Authenticates host sessions, authorizes each action, rejects CSRF mutations, and injects existing scoped admin credentials server-side."
        hindsight = softwareSystem "Hindsight" "Only implemented memory backend."

        memoryRouter = softwareSystem "Memory Router" "Principal authorization, policy, and security boundary between agent integrations and Hindsight." {
            api = container "Memory Router API" "Hindsight-compatible HTTP facade, routing, policy, security, quarantine, and review API." "Python 3.12 / FastAPI / Uvicorn" {
                lifecycle = component "Runtime Lifecycle" "Starts dependencies, validates deployment configuration, recovers stale reviews, and shuts resources down."
                http = component "HTTP/API Entry & Auth" "Bounds request bodies, parses strict JSON, normalizes paths, authenticates router/admin requests, and dispatches supported routes."
                facade = component "Hindsight Compatibility Facade" "Handles supported bank, config, document, mental-model, and reflect endpoints and preserves their response contracts."
                principals = component "Principal Authentication / Grants" "Authenticates principal credentials and authorizes each bank and operation scope; denied requests stop before Hindsight."
                registry = component "Legacy Writer Registry" "Maps legacy writer IDs to configured write/read banks; principal mode uses explicitly authorized banks."
                policy = component "Policy Orchestration" "Coordinates retain/recall decisions, recall fan-out, suppression, and degradation rules."
                scanning = component "Security Scanning" "Applies router deterministic rules plus Agent Memory Guard/OWASP-oriented checks, canonicalization, cross-field scanning, and encoded-payload inspection."
                limits = component "Request/Response Limits & Rate Limiting" "Enforces request bounds and Hindsight/quarantine/auth consumption budgets."
                gateway = component "Hindsight Gateway" "Performs bounded HTTP calls to Hindsight and validates upstream responses."
                quarantine = component "Quarantine Admission / Storage" "Encrypts evidence, enforces quarantine admission/capacity, and persists review state and audit events."
                review = component "Review Lifecycle" "Verifies exact decrypted evidence and coordinates approve/reject/postpone state transitions and Hindsight side effects."
                maintenance = component "Maintenance" "Recovers stale reviews, expires pending items, and prunes old audit events."
                observability = component "Observability" "Propagates request IDs and emits bounded operational/security diagnostics without raw upstream payloads."
            }

            quarantineStorage = container "Quarantine Storage" "Encrypted quarantine/review state, audit history, and shared rate-limit state when PostgreSQL is used." "SQLite (single-node) or PostgreSQL (clustered)" "Database"
            console = container "Quarantine Console" "Standalone token session or optional same-origin host authentication. Local WebCrypto decryption; embed layout retains actions." "React / TypeScript"
            reviewTool = container "Offline Review Tooling" "Decrypts exported quarantine envelopes outside the router process. The private key is supplied locally and is never available to Memory Router." "Python CLI" "Offline"
        }

        operator -> console "Reviews quarantine in the browser" "HTTPS"
        console -> api "Standalone: existing scoped admin credentials" "HTTP/JSON + scoped Bearer"
        console -> http "Reads encrypted evidence and submits scoped review actions" "HTTP/JSON + scoped Bearer"
        console -> hostProxy "Host mode: same-origin session; no browser admin bearer" "HTTPS + host session"
        hostProxy -> api "Authorized action with existing scoped admin credential" "HTTP/JSON + scoped Bearer"

        agents -> bridge "Calls plugin, harness adapter, or MCP tools" "In-process / stdio MCP"
        bridge -> api "Uses explicit bank and principal credential" "HTTPS/JSON + Bearer"
        bridge -> retainQueue "Queues transient retain failures and replays FIFO" "Local files"
        api -> bridge "Returns authorized results or bounded errors" "HTTPS/JSON"
        bridge -> agents "Returns tool results and delivery outcomes" "In-process / stdio MCP"
        api -> hindsight "Calls supported Hindsight endpoints" "HTTP/JSON"
        api -> quarantineStorage "Persists quarantine/review state and, in PostgreSQL mode, shared rate-limit state" "SQL"
        operator -> api "Uses quarantine review API" "Admin HTTP/JSON + scoped Bearer"
        operator -> http "Reads quarantine records and submits review decisions" "Admin HTTP/JSON + scoped Bearer"
        operator -> reviewTool "Decrypts exported evidence with private key" "Local CLI/stdin + file"

        bridge -> http "Sends supported Hindsight-compatible requests" "HTTP/JSON + Bearer"
        http -> principals "Authenticates principal token and checks bank/scope grant"
        principals -> observability "Records bounded authorization decisions"
        http -> facade "Dispatches supported compatibility routes"
        http -> policy "Dispatches retain/recall"
        http -> review "Dispatches quarantine review operations"
        http -> limits "Applies body/auth/admin limits"
        http -> observability "Establishes request context"

        facade -> registry "Resolves writer and target bank"
        facade -> scanning "Scans request and Hindsight response"
        facade -> limits "Applies operation bounds/quotas"
        facade -> gateway "Forwards allowed operation"
        gateway -> hindsight "Performs bounded Hindsight request" "HTTP/JSON"
        facade -> quarantine "Audits blocked requests/responses"

        policy -> registry "Resolves writer and read/write banks"
        policy -> scanning "Scans retain/recall requests and recalled results"
        policy -> limits "Applies request bounds/quotas"
        policy -> gateway "Retains/recalls allowed content"
        policy -> quarantine "Queues unknown/suspicious evidence and reads review state"
        policy -> observability "Reports bounded degradation diagnostics"

        review -> quarantine "Reads/claims/finalizes review state"
        review -> registry "Re-resolves legacy writer before retain approval"
        review -> principals "Rechecks original principal retain grant for the quarantined bank"
        review -> scanning "Re-scans retained request before approval"
        review -> limits "Re-applies bounds/quotas before Hindsight side effect"
        review -> gateway "Retains approved request or invalidates rejected recalled memory"

        quarantine -> limits "Applies quarantine admission budgets"
        quarantine -> quarantineStorage "Stores encrypted evidence and audit/review state" "SQL"
        limits -> quarantineStorage "Uses shared rate-limit state in PostgreSQL mode" "SQL"
        maintenance -> quarantineStorage "Recovers, expires, and prunes" "SQL"
        lifecycle -> quarantineStorage "Opens and validates storage; initializes PostgreSQL limiter when configured" "SQL"
        lifecycle -> limits "Initializes configured limiters"
        lifecycle -> registry "Loads legacy writer registry"
        lifecycle -> principals "Loads and validates principal registry"
        lifecycle -> gateway "Creates/closes Hindsight client"
        lifecycle -> maintenance "Starts/stops maintenance task"
        gateway -> observability "Propagates request ID and reports bounded upstream failures"

        singleNode = deploymentEnvironment "Single Node" {
            deploymentNode "Agent host" "Agent runtime and installed integrations" {
                softwareSystemInstance agents
                containerInstance bridge
                containerInstance retainQueue
            }
            deploymentNode "Memory Router host" "Single Memory Router process" "Docker or host process" {
                containerInstance api
                deploymentNode "Local data volume" "Router-local persistent storage" "SQLite" {
                    containerInstance quarantineStorage
                }
            }
            deploymentNode "Hindsight host" "Hindsight deployment" {
                softwareSystemInstance hindsight
            }
            deploymentNode "Reviewer workstation" "Private-key boundary" {
                containerInstance reviewTool
            }
        }

        clustered = deploymentEnvironment "Clustered" {
            deploymentNode "Agent host" "Agent runtime and installed integrations" {
                softwareSystemInstance agents
                containerInstance bridge
                containerInstance retainQueue
            }
            deploymentNode "Memory Router cluster" "Two or more router replicas" {
                adminIngress = infrastructureNode "External shared admin rate limiter" "Required in clustered mode for /admin/* before requests reach a replica." "Reverse proxy / shared limiter"
                routerA = containerInstance api
                routerB = containerInstance api
                adminIngress -> routerA "Forwards rate-limited /admin/* traffic" "HTTP"
                adminIngress -> routerB "Forwards rate-limited /admin/* traffic" "HTTP"
            }
            deploymentNode "PostgreSQL" "Shared router persistence" "PostgreSQL" {
                containerInstance quarantineStorage
            }
            deploymentNode "Hindsight host" "Hindsight deployment" {
                softwareSystemInstance hindsight
            }
            deploymentNode "Reviewer workstation" "Private-key boundary" {
                containerInstance reviewTool
            }
        }
    }

    views {
        systemContext memoryRouter "SystemContext" "Current supported topology and review boundary." {
            include agents integrations memoryRouter hindsight operator hostProxy
            autoLayout lr
        }

        container memoryRouter "Containers" "Memory Router runtime and dependency boundaries." {
            include bridge api quarantineStorage reviewTool console hindsight operator hostProxy
            autoLayout lr
        }

        component api "Components" "Memory Router API components at one abstraction level." {
            include *
            autoLayout lr
        }

        dynamic api "StartupShutdown" "Startup and shutdown lifecycle." {
            lifecycle -> quarantineStorage "Open and validate quarantine storage; recover stale review state"
            lifecycle -> limits "Initialize process-local or PostgreSQL-backed limiters"
            lifecycle -> registry "Load legacy writer registry"
            lifecycle -> principals "Load and validate principal registry"
            lifecycle -> gateway "Create Hindsight gateway"
            lifecycle -> maintenance "Start maintenance task when enabled"
            lifecycle -> maintenance "On shutdown: cancel maintenance task"
            lifecycle -> gateway "Close Hindsight gateway"
            lifecycle -> quarantineStorage "Close storage and PostgreSQL limiter pool"
            autoLayout lr
        }

        dynamic api "Retain" "Retain request security and routing flow." {
            bridge -> http "POST memory retain request"
            http -> principals "Principal mode: authenticate and authorize memory.retain for the requested bank"
            http -> limits "Bound body, strict JSON/schema, retain limits"
            http -> policy "Dispatch validated retain"
            policy -> registry "Legacy mode only: resolve writer and write bank"
            policy -> scanning "Scan all request strings/keys"
            policy -> quarantine "Unsafe retain (or unknown legacy writer): encrypt and quarantine; stop"
            policy -> limits "If allowed: consume Hindsight retain budget"
            policy -> gateway "Retain to assigned Hindsight write bank"
            gateway -> hindsight "POST retain"
            autoLayout lr
        }

        dynamic api "Recall" "Recall request, Hindsight fan-out, and response security flow." {
            bridge -> http "POST memory recall request"
            http -> principals "Principal mode: authenticate and authorize memory.recall for the requested bank"
            http -> limits "Bound body, strict JSON/schema, recall limits"
            http -> policy "Dispatch validated recall"
            policy -> registry "Legacy mode only: resolve writer and read banks"
            policy -> scanning "Scan recall request"
            policy -> quarantine "Unsafe query (or unknown legacy writer): audit/quarantine and return empty results"
            policy -> limits "If allowed: consume Hindsight recall budget"
            policy -> gateway "Principal mode: requested bank; legacy mode: read-bank fan-out"
            gateway -> hindsight "POST recall per allowed bank"
            policy -> quarantine "Check review state for recalled memories"
            policy -> scanning "Scan recalled results and supplemental fields before release"
            policy -> quarantine "Unsafe provider content is quarantined/audited and suppressed"
            autoLayout lr
        }

        dynamic api "CompatibilityOperations" "Shared policy flow for supported Hindsight compatibility operations." {
            bridge -> http "Bank/config/mental-model/reflect request"
            http -> principals "Principal mode: authenticate and check operation scope for requested bank"
            http -> facade "Dispatch supported compatibility operation"
            facade -> registry "Legacy mode only: resolve writer to configured bank"
            facade -> quarantine "If legacy writer is unknown: audit bounded security event and reject"
            facade -> scanning "Scan path/query/body using read or write semantics"
            facade -> quarantine "If request is suspicious: audit and reject"
            facade -> limits "Apply reflect bounds when needed; consume recall or retain budget"
            facade -> gateway "Forward authorized bank; rewrite legacy writer ID to assigned bank"
            gateway -> hindsight "PUT/PATCH/GET/POST/DELETE supported operation"
            facade -> scanning "Scan provider response before release"
            facade -> quarantine "If provider response is unsafe: audit and reject"
            autoLayout lr
        }

        dynamic api "PrincipalAuthorization" "Principal credentials and bank/scope grants gate all memory operations." {
            bridge -> http "Send requested bank and bearer token; claimed agent is informational"
            http -> principals "Authenticate active credential; reject invalid token or mismatched agent claim"
            http -> limits "Apply principal operation rate limit"
            http -> principals "Check exact bank and operation scope; deny before backend access"
            principals -> observability "Record allow/deny without tokens or memory content"
            http -> limits "Enforce principal body and concurrency limits"
            http -> policy "Only authorized retain/recall reaches policy (compatibility routes use facade)"
            autoLayout lr
        }

        dynamic integrations "IntegrationReads" "Client-side multi-bank reads preserve server authorization and bounded results." {
            agents -> bridge "Recall or reflect through configured integration"
            bridge -> api "Resolve trusted principal and readable banks; call each bank within shared budget"
            api -> hindsight "Authorize, scan, and execute each allowed bank request"
            api -> bridge "Collect responses: any 401/403 discards the entire read result"
            bridge -> agents "Bounded results: recall content deduplication; transient failures permit partial reads"
            autoLayout lr
        }

        dynamic integrations "RetainReplay" "Configured integration retain queues handle transient outages without changing bank authority." {
            agents -> bridge "Retain using principal's configured write bank"
            bridge -> api "Attempt authenticated retain with stable operation ID"
            bridge -> retainQueue "Transient failure only: enqueue within shared capacity; 401/403 never enqueue"
            bridge -> retainQueue "Replay under OS lock; preserve FIFO and check expiry"
            bridge -> api "Re-resolve credentials and current write bank; send only if bank still matches"
            bridge -> retainQueue "Remove delivered items; denied/permanent failures remain for review"
            bridge -> retainQueue "After five transient replay failures: abandon item and report delivery loss"
            autoLayout lr
        }

        dynamic api "QuarantineReview" "Encrypted evidence is decrypted locally; review decisions control release or invalidation." {
            policy -> quarantine "Submit suspicious evidence (or unknown legacy writer)"
            quarantine -> quarantineStorage "After admission limits: encrypt evidence and persist review state"
            operator -> console "Open quarantine console with scoped review access"
            console -> http "Fetch encrypted evidence; optional host mode uses authenticated proxy"
            operator -> console "Decrypt and inspect locally with WebCrypto; private key stays in browser"
            operator -> reviewTool "Alternative: decrypt exported envelope locally with CLI and private key"
            operator -> http "Approve with exact decrypted evidence, or reject/postpone"
            http -> review "Authenticate scoped admin action; verify approval digest and claim state"
            review -> principals "Retain approval: recheck original principal grant (legacy mode rechecks registry)"
            review -> scanning "Retain approval: parse, bound, and re-scan original request"
            review -> gateway "Retain approval writes; recalled-memory rejection invalidates"
            gateway -> hindsight "Perform checkpointed retain or invalidate only when required"
            review -> quarantine "Finalize: recall approval allows; retain rejection blocks; postpone defers"
            autoLayout lr
        }

        dynamic api "QuarantineRecovery" "Ambiguous side effects require verified reconciliation, never blind replay." {
            review -> quarantine "Ambiguous Hindsight outcome: preserve side-effect-started checkpoint"
            operator -> http "Independently verify Hindsight outcome, then fetch current item snapshot"
            operator -> http "Reconcile with expected digest and update timestamp"
            http -> review "Authenticate scoped admin action and dispatch reconciliation"
            review -> quarantine "Compare snapshot; confirmed applied finalizes without another upstream call"
            review -> quarantine "Confirmed not applied moves to postponed for a normal retry"
            autoLayout lr
        }

        deployment * singleNode "SingleNode" "Single-node deployment with SQLite." {
            include *
            autoLayout lr
        }

        deployment * clustered "Clustered" "Clustered deployment with PostgreSQL and external shared admin throttling." {
            include *
            autoLayout lr
        }

        styles {
            element "Person" {
                shape Person
            }
            element "Database" {
                shape Cylinder
            }
            element "Offline" {
                shape Folder
            }
        }

        properties {
            "structurizr.metadata" "false"
        }
    }
}

