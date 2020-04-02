// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

pub mod definition;
#[cfg(any(test, feature = "fuzzing"))]
pub mod proptest_proof;

#[cfg(test)]
#[path = "unit_tests/proof_test.rs"]
mod proof_test;

use libra_crypto::{
    hash::{CryptoHash, CryptoHasher, SparseMerkleInternalHasher},
    HashValue,
};
use libra_crypto_derive::CryptoHasher;
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
        state.write(self.left_child.as_ref());
        state.write(self.right_child.as_ref());
        state.finish()
    }
}

pub type SparseMerkleInternalNode = MerkleTreeInternalNode<SparseMerkleInternalHasher>;

#[derive(CryptoHasher)]
pub struct SparseMerkleLeafNode {
    key: HashValue,
    value_hash: HashValue,
}

impl SparseMerkleLeafNode {
    pub fn new(key: HashValue, value_hash: HashValue) -> Self {
        SparseMerkleLeafNode { key, value_hash }
    }
}

impl CryptoHash for SparseMerkleLeafNode {
    type Hasher = SparseMerkleLeafNodeHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        state.write(self.key.as_ref());
        state.write(self.value_hash.as_ref());
        state.finish()
    }
}
