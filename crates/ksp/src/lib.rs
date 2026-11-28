//! The `ksp` command surface, its exit-code contract and its output rules.
//!
//! Every operation is one foreground invocation: the binary starts, does its
//! work and exits. It opens no listening socket and holds no state between runs
//! (NFR-001, NFR-002).

#![deny(missing_docs)]

pub mod admin;
pub mod admission;
pub mod agent;
pub mod agent_index;
pub mod app;
pub mod arm;
pub mod audit;
pub mod audit_verify;
pub mod audit_view;
pub mod backend;
pub mod capability_config;
pub mod commands;
pub mod config;
pub mod consume;
pub mod deliver;
pub mod deployment;
pub mod edges;
pub mod establish;
pub mod exit;
pub mod grant;
pub mod import;
pub mod install;
pub mod keys;
pub mod layout;
pub mod ledgers;
pub mod lifecycle;
pub mod output;
pub mod policy_view;
pub mod probe;
pub mod process;
pub mod publication;
pub mod registry;
pub mod run;
pub mod run_gate;
pub mod secret;
pub mod storegroup;
pub mod sweep;
pub mod token;
pub mod vault;

pub use exit::{Outcome, SUCCESS};
