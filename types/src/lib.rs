// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

pub mod account_state_blob;
pub mod proof;
#[cfg(any(test, feature = "fuzzing"))]
pub mod proptest_types;
#[cfg(any(test, feature = "fuzzing"))]
pub mod test_helpers;
pub mod transaction {
    pub type Version = u64;

    pub const PRE_GENESIS_VERSION: Version = u64::max_value();
}

#[cfg(test)]
mod unit_tests;
