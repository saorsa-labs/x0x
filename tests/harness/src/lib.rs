//! x0x test harness — shared infrastructure for integration, property, and fuzz tests.
//!
//! Provides:
//! - `AgentCluster`: 3-agent daemon orchestration (alice, bob, charlie)
//! - `coverage`: API endpoint coverage enforcement
//! - `strategies`: proptest strategies for all x0x types
//! - `models`: Reference model oracles for model-based testing
//! - `scenarios`: Shared test scenario definitions

pub mod cluster;
pub mod coverage;
pub mod daemon;
pub mod models;
pub mod scenarios;
pub mod strategies;
