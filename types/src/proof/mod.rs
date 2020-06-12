// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

pub mod definition;
#[cfg(any(test, feature = "fuzzing"))]
pub mod proptest_proof;

#[cfg(test)]
mod unit_tests;

use libra_crypto::{
    hash::{CryptoHash, CryptoHasher, SparseMerkleInternalHasher},
    HashValue,
};
use libra_crypto_derive::CryptoHasher;
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

pub use self::definition::{SparseMerkleProof, SparseMerkleRangeProof};

#[cfg(any(test, feature = "fuzzing"))]
pub use self::definition::{TestAccumulatorProof, TestAccumulatorRangeProof};

pub struct MerkleTreeInternalNode<H> {
    left_child: HashValue,
    right_child: HashValue,
    hasher: PhantomData<H>,
}

impl<H: CryptoHasher> MerkleTreeInternalNode<H> {
    pub fn new(left_child: HashValue, right_child: HashValue) -> Self {
        Self {
            left_child,
            right_child,
            hasher: PhantomData,
        }
    }
}

impl<H: CryptoHasher> CryptoHash for MerkleTreeInternalNode<H> {
    type Hasher = H;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        state.update(self.left_child.as_ref());
        state.update(self.right_child.as_ref());
        state.finish()
    }
}

pub type SparseMerkleInternalNode = MerkleTreeInternalNode<SparseMerkleInternalHasher>;

#[derive(Clone, Copy, CryptoHasher, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct SparseMerkleLeafNode {
    key: HashValue,
    value_hash: HashValue,
}

impl SparseMerkleLeafNode {
    pub fn new(key: HashValue, value_hash: HashValue) -> Self {
        SparseMerkleLeafNode { key, value_hash }
    }

    pub fn key(&self) -> HashValue {
        self.key
    }

    pub fn value_hash(&self) -> HashValue {
        self.value_hash
    }
}

impl CryptoHash for SparseMerkleLeafNode {
    type Hasher = SparseMerkleLeafNodeHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        state.update(self.key.as_ref());
        state.update(self.value_hash.as_ref());
        state.finish()
    }
}
