// Copyright (c) 2023-2024 Martin Olivier <martin.olivier@live.fr>
//
//! GUI-facing type definitions and re-exports.

pub use aeroshield_common::types::{AP, AttackTarget, Settings};

pub struct BruteforceCharsetParams {
    pub lowercase: bool,
    pub uppercase: bool,
    pub numbers: bool,
    pub symbols: bool,
}

pub enum BruteforceCharset {
    Params(BruteforceCharsetParams),
    Specific(String),
}
