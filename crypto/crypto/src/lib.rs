// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! A library supplying various cryptographic primitives

pub mod hash;

#[cfg(test)]
mod unit_tests;

pub use hash::HashValue;

// Reexport once_cell for use in CryptoHasher Derive implementation
#[doc(hidden)]
pub use once_cell as _once_cell;
