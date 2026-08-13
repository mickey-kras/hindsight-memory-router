workspace "Hindsight Memory Router" "As-built architecture" {
    model {
        operator = person "Operator / Reviewer" "Reviews quarantined evidence and submits review decisions."

        openclaw = softwareSystem "OpenClaw (Hindsight plugin)" "Current supported client integration."
        hindsight = softwareSystem "Hindsight" "Only implemented memory backend."

        memoryRouter = softwareSystem "Memory Router" "Policy and security boundary between the OpenClaw Hindsight plugin and Hindsight." {
            api = container "Memory Router API" "Hindsight-compatible HTTP facade, routing, policy, security, quarantine, and review API." "Python 3.12 / FastAPI / Uvicorn" {
                lifecycle = component "Runtime Lifecycle" "Starts dependencies, validates deployment configuration, recovers stale reviews, and shuts resources down."
                http = component "HTTP/API Entry & Auth" "Bounds request bodies, parses strict JSON, normalizes paths, authenticates router/admin requests, and dispatches supported routes."
                facade = component "Hindsight/OpenClaw Compatibility Facade" "Handles the additional Hindsight endpoints currently used by OpenClaw and preserves their response contracts."
                registry = component "Writer Registry / Bank Routing" "Maps configured writer IDs to Hindsight write/read banks."
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
            reviewTool = container "Offline Review Tooling" "Decrypts exported quarantine envelopes outside the router process. The private key is supplied locally and is never available to Memory Router." "Python CLI" "Offline"
        }

        openclaw -> api "Uses Hindsight-compatible API" "HTTP/JSON + Bearer"
        api -> hindsight "Calls supported Hindsight endpoints" "HTTP/JSON"
        api -> quarantineStorage "Persists quarantine/review state and, in PostgreSQL mode, shared rate-limit state" "SQL"
        operator -> api "Uses quarantine review API" "Admin HTTP/JSON + scoped Bearer"
        operator -> http "Reads quarantine records and submits review decisions" "Admin HTTP/JSON + scoped Bearer"
        operator -> reviewTool "Decrypts exported evidence with private key" "Local CLI/stdin + file"

        openclaw -> http "Sends supported Hindsight-compatible requests" "HTTP/JSON + Bearer"
        http -> facade "Dispatches OpenClaw compatibility routes"
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
        review -> registry "Re-resolves writer before retain approval"
        review -> scanning "Re-scans retained request before approval"
        review -> limits "Re-applies bounds/quotas before Hindsight side effect"
        review -> gateway "Retains approved request or invalidates rejected recalled memory"

        quarantine -> limits "Applies quarantine admission budgets"
        quarantine -> quarantineStorage "Stores encrypted evidence and audit/review state" "SQL"
        limits -> quarantineStorage "Uses shared rate-limit state in PostgreSQL mode" "SQL"
        maintenance -> quarantineStorage "Recovers, expires, and prunes" "SQL"
        lifecycle -> quarantineStorage "Opens and validates storage; initializes PostgreSQL limiter when configured" "SQL"
        lifecycle -> limits "Initializes configured limiters"
        lifecycle -> registry "Loads writer registry"
        lifecycle -> gateway "Creates/closes Hindsight client"
        lifecycle -> maintenance "Starts/stops maintenance task"
        gateway -> observability "Propagates request ID and reports bounded upstream failures"

        singleNode = deploymentEnvironment "Single Node" {
            deploymentNode "OpenClaw host" "OpenClaw runtime" {
                softwareSystemInstance openclaw
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
            deploymentNode "OpenClaw host" "OpenClaw runtime" {
                softwareSystemInstance openclaw
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
            include openclaw memoryRouter hindsight operator
            autoLayout lr
        }

        container memoryRouter "Containers" "Memory Router runtime and dependency boundaries." {
            include openclaw api quarantineStorage reviewTool hindsight operator
            autoLayout lr
        }

        component api "Components" "Memory Router API components at one abstraction level." {
            include *
            autoLayout lr
        }

        dynamic api "StartupShutdown" "Startup and shutdown lifecycle." {
            lifecycle -> quarantineStorage "Open and validate quarantine storage; recover stale review state"
            lifecycle -> limits "Initialize process-local or PostgreSQL-backed limiters"
            lifecycle -> registry "Load writer registry"
            lifecycle -> gateway "Create Hindsight gateway"
            lifecycle -> maintenance "Start maintenance task when enabled"
            lifecycle -> maintenance "On shutdown: cancel maintenance task"
            lifecycle -> gateway "Close Hindsight gateway"
            lifecycle -> quarantineStorage "Close storage and PostgreSQL limiter pool"
            autoLayout lr
        }

        dynamic api "Retain" "Retain request security and routing flow." {
            openclaw -> http "POST memory retain request"
            http -> limits "Bound body, strict JSON/schema, retain limits"
            http -> policy "Dispatch validated retain"
            policy -> registry "Resolve writer and write bank"
            policy -> scanning "Scan all request strings/keys"
            policy -> quarantine "If writer is unknown or scan is unsafe: encrypt and queue; stop"
            policy -> limits "If allowed: consume Hindsight retain budget"
            policy -> gateway "Retain to assigned Hindsight write bank"
            gateway -> hindsight "POST retain"
            autoLayout lr
        }

        dynamic api "Recall" "Recall request, Hindsight fan-out, and response security flow." {
            openclaw -> http "POST memory recall request"
            http -> limits "Bound body, strict JSON/schema, recall limits"
            http -> policy "Dispatch validated recall"
            policy -> registry "Resolve writer and allowed read banks"
            policy -> scanning "Scan recall request"
            policy -> quarantine "If writer is unknown or query is unsafe: audit/quarantine and return empty results"
            policy -> limits "If allowed: consume Hindsight recall budget"
            policy -> gateway "Recall allowed read banks in parallel"
            gateway -> hindsight "POST recall per allowed bank"
            policy -> quarantine "Check review state for recalled memories"
            policy -> scanning "Scan recalled results and supplemental fields before release"
            policy -> quarantine "Unsafe provider content is quarantined/audited and suppressed"
            autoLayout lr
        }

        dynamic api "QuarantineReview" "Quarantine admission and human review flow." {
            policy -> quarantine "Submit unknown/suspicious evidence"
            quarantine -> limits "Apply quarantine write/requarantine/distinct-family limits"
            quarantine -> quarantineStorage "Encrypt with public key, enforce capacity, persist state/audit"
            operator -> http "Read encrypted quarantine item"
            operator -> reviewTool "Decrypt exported envelope locally with private key"
            operator -> http "Submit exact decrypted evidence with approve/reject/postpone decision"
            http -> review "Authenticate scoped admin request and dispatch review"
            review -> quarantine "Verify exact digest and claim review state"
            review -> scanning "For retain approval: parse, bound, and re-scan original request"
            review -> gateway "When required: perform checkpointed Hindsight retain/invalidate side effect"
            gateway -> hindsight "Retain approved request or invalidate rejected memory"
            review -> quarantine "Finalize review state/audit; encrypted payload removed where applicable"
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
            "mermaid.title" "true"
            "mermaid.sequenceDiagram" "true"
        }
    }
}
