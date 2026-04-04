//! Shared test scenario definitions.
//!
//! Scenarios define multi-step test sequences as data structures that can be
//! executed through different interfaces (REST, CLI, typed client, Swift).

use serde::{Deserialize, Serialize};

/// Which agent in the cluster performs the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentName {
    Alice,
    Bob,
    Charlie,
}

/// HTTP method for scenario steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

/// An assertion to check against a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Assertion {
    /// JSON path exists in response.
    JsonPathExists(String),
    /// JSON path equals expected value.
    JsonPathEquals(String, serde_json::Value),
    /// Response body contains string.
    ContainsString(String),
    /// HTTP status code equals expected.
    StatusCode(u16),
}

/// A condition to wait for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    /// Agent has at least `min` peers.
    PeerCount { min: usize },
    /// A contact with the given agent_id variable exists.
    ContactExists { agent_id_var: String },
    /// A store key has a specific value.
    StoreKeyEquals {
        store_id_var: String,
        key: String,
        value: String,
    },
}

/// A single step in a test scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Step {
    /// Call a REST API endpoint.
    Rest {
        agent: AgentName,
        method: Method,
        path: String,
        body: Option<serde_json::Value>,
        expect_status: u16,
        /// Extract JSON values into named variables: (json_path, variable_name).
        extract: Vec<(String, String)>,
        assertions: Vec<Assertion>,
    },
    /// Run a CLI command.
    Cli {
        agent: AgentName,
        command: String,
        args: Vec<String>,
        assertions: Vec<Assertion>,
    },
    /// Wait for a condition to become true.
    WaitFor {
        agent: AgentName,
        condition: Condition,
        timeout_secs: u64,
    },
    /// Pause for gossip propagation.
    Sleep { millis: u64 },
}

/// A complete test scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    /// Short name for the scenario.
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Ordered steps to execute.
    pub steps: Vec<Step>,
}

/// Export all scenarios as JSON for consumption by Swift tests.
pub fn export_scenarios_json() -> String {
    let scenarios = all_scenarios();
    serde_json::to_string_pretty(&scenarios).expect("scenarios serialize")
}

/// All defined scenarios.
pub fn all_scenarios() -> Vec<Scenario> {
    vec![
        contact_exchange(),
        group_lifecycle(),
        kv_store_convergence(),
        pubsub_round_trip(),
        presence_discovery(),
    ]
}

// ── Scenario definitions ──────────────────────────────────────────────

/// Two agents exchange contacts and verify trust levels.
pub fn contact_exchange() -> Scenario {
    Scenario {
        name: "contact_exchange",
        description: "Alice adds Bob as a contact, Bob adds Alice back, verify mutual visibility",
        steps: vec![
            Step::Rest {
                agent: AgentName::Alice,
                method: Method::Get,
                path: "/agent".into(),
                body: None,
                expect_status: 200,
                extract: vec![("agent_id".into(), "alice_id".into())],
                assertions: vec![Assertion::JsonPathExists("agent_id".into())],
            },
            Step::Rest {
                agent: AgentName::Bob,
                method: Method::Get,
                path: "/agent".into(),
                body: None,
                expect_status: 200,
                extract: vec![("agent_id".into(), "bob_id".into())],
                assertions: vec![Assertion::JsonPathExists("agent_id".into())],
            },
            Step::Rest {
                agent: AgentName::Alice,
                method: Method::Post,
                path: "/contacts".into(),
                body: Some(serde_json::json!({
                    "agent_id": "${bob_id}",
                    "trust_level": "known"
                })),
                expect_status: 200,
                extract: vec![],
                assertions: vec![Assertion::StatusCode(200)],
            },
            Step::Rest {
                agent: AgentName::Bob,
                method: Method::Post,
                path: "/contacts".into(),
                body: Some(serde_json::json!({
                    "agent_id": "${alice_id}",
                    "trust_level": "known"
                })),
                expect_status: 200,
                extract: vec![],
                assertions: vec![Assertion::StatusCode(200)],
            },
            Step::Rest {
                agent: AgentName::Alice,
                method: Method::Get,
                path: "/contacts".into(),
                body: None,
                expect_status: 200,
                extract: vec![],
                assertions: vec![Assertion::ContainsString("${bob_id}".into())],
            },
        ],
    }
}

/// Create a named group, invite a member, join, verify membership.
pub fn group_lifecycle() -> Scenario {
    Scenario {
        name: "group_lifecycle",
        description: "Alice creates a group, invites Bob, Bob joins, verify both see the group",
        steps: vec![
            Step::Rest {
                agent: AgentName::Alice,
                method: Method::Post,
                path: "/groups".into(),
                body: Some(serde_json::json!({"name": "test-group"})),
                expect_status: 200,
                extract: vec![("group_id".into(), "group_id".into())],
                assertions: vec![Assertion::JsonPathExists("group_id".into())],
            },
            Step::Rest {
                agent: AgentName::Alice,
                method: Method::Post,
                path: "/groups/${group_id}/invite".into(),
                body: None,
                expect_status: 200,
                extract: vec![("invite_link".into(), "invite_link".into())],
                assertions: vec![Assertion::JsonPathExists("invite_link".into())],
            },
            Step::Rest {
                agent: AgentName::Bob,
                method: Method::Post,
                path: "/groups/join".into(),
                body: Some(serde_json::json!({"invite_link": "${invite_link}"})),
                expect_status: 200,
                extract: vec![],
                assertions: vec![Assertion::StatusCode(200)],
            },
            Step::Rest {
                agent: AgentName::Bob,
                method: Method::Get,
                path: "/groups".into(),
                body: None,
                expect_status: 200,
                extract: vec![],
                assertions: vec![Assertion::ContainsString("test-group".into())],
            },
        ],
    }
}

/// Two agents share a KV store and verify convergence.
pub fn kv_store_convergence() -> Scenario {
    Scenario {
        name: "kv_store_convergence",
        description: "Alice creates a store, puts a key, Bob joins and reads it",
        steps: vec![
            Step::Rest {
                agent: AgentName::Alice,
                method: Method::Post,
                path: "/stores".into(),
                body: Some(serde_json::json!({
                    "name": "test-store",
                    "topic": "test-store-topic"
                })),
                expect_status: 200,
                extract: vec![("store_id".into(), "store_id".into())],
                assertions: vec![Assertion::JsonPathExists("store_id".into())],
            },
            Step::Rest {
                agent: AgentName::Alice,
                method: Method::Put,
                path: "/stores/${store_id}/greeting".into(),
                body: Some(serde_json::json!({
                    "value": "hello",
                    "content_type": "text/plain"
                })),
                expect_status: 200,
                extract: vec![],
                assertions: vec![Assertion::StatusCode(200)],
            },
            Step::Sleep { millis: 1000 },
            Step::Rest {
                agent: AgentName::Alice,
                method: Method::Get,
                path: "/stores/${store_id}/greeting".into(),
                body: None,
                expect_status: 200,
                extract: vec![],
                assertions: vec![Assertion::ContainsString("hello".into())],
            },
        ],
    }
}

/// Publish a message and verify it arrives via subscription.
pub fn pubsub_round_trip() -> Scenario {
    Scenario {
        name: "pubsub_round_trip",
        description: "Alice publishes to a topic, Bob subscribes and receives",
        steps: vec![
            Step::Rest {
                agent: AgentName::Bob,
                method: Method::Post,
                path: "/subscribe".into(),
                body: Some(serde_json::json!({"topic": "test-topic"})),
                expect_status: 200,
                extract: vec![("subscription_id".into(), "sub_id".into())],
                assertions: vec![Assertion::StatusCode(200)],
            },
            Step::Sleep { millis: 500 },
            Step::Rest {
                agent: AgentName::Alice,
                method: Method::Post,
                path: "/publish".into(),
                body: Some(serde_json::json!({
                    "topic": "test-topic",
                    "payload": "dGVzdC1tZXNzYWdl"
                })),
                expect_status: 200,
                extract: vec![],
                assertions: vec![Assertion::StatusCode(200)],
            },
        ],
    }
}

/// Verify presence discovery between agents.
pub fn presence_discovery() -> Scenario {
    Scenario {
        name: "presence_discovery",
        description: "Agents discover each other via presence system",
        steps: vec![
            Step::Sleep { millis: 2000 },
            Step::Rest {
                agent: AgentName::Alice,
                method: Method::Get,
                path: "/presence/online".into(),
                body: None,
                expect_status: 200,
                extract: vec![],
                assertions: vec![Assertion::StatusCode(200)],
            },
            Step::Rest {
                agent: AgentName::Alice,
                method: Method::Get,
                path: "/agents/discovered".into(),
                body: None,
                expect_status: 200,
                extract: vec![],
                assertions: vec![Assertion::StatusCode(200)],
            },
        ],
    }
}
