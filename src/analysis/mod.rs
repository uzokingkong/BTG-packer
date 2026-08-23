pub mod cfg_seed;
pub mod code_pointers;
pub mod crt;
pub mod entropy;
pub mod indirect_resolver;
pub mod indirect_targets;
pub mod metrics;
pub mod pointer_tables;
pub mod program_model;
pub mod program_model_builder;
pub mod switch_producer;
pub mod switch_targets;
pub mod value_flow;

#[allow(unused_imports)]
pub use metrics::{CfgEdgeCounts, MetricsAnalyzer, ObfuscationMetrics};
