// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use libra_crypto::{
    hash::{CryptoHash, CryptoHasher},
    HashValue,
};
use libra_crypto_derive::CryptoHasher;
#[cfg(any(test, feature = "fuzzing"))]
use proptest::{arbitrary::Arbitrary, prelude::*};
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher)]
pub struct AccountStateBlob {
    blob: Vec<u8>,
}

impl AsRef<[u8]> for AccountStateBlob {
    fn as_ref(&self) -> &[u8] {
        &self.blob
    }
}

impl From<AccountStateBlob> for Vec<u8> {
    fn from(account_state_blob: AccountStateBlob) -> Vec<u8> {
        account_state_blob.blob
    }
}

impl From<Vec<u8>> for AccountStateBlob {
    fn from(blob: Vec<u8>) -> AccountStateBlob {
        AccountStateBlob { blob }
    }
}

impl CryptoHash for AccountStateBlob {
    type Hasher = AccountStateBlobHasher;

    fn hash(&self) -> HashValue {
        let mut hasher = Self::Hasher::default();
        hasher.write(&self.blob);
        hasher.finish()
    }
}

#[cfg(any(test, feature = "fuzzing"))]
prop_compose! {
    fn account_state_blob_strategy()(account_resource in any::<AccountResource>(), balance_resource in any::<BalanceResource>()) -> AccountStateBlob {
        AccountStateBlob::try_from((&account_resource, &balance_resource)).unwrap()
    }
}

#[cfg(any(test, feature = "fuzzing"))]
impl Arbitrary for AccountStateBlob {
    type Parameters = ();
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        account_state_blob_strategy().boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use lcs::test_helpers::assert_canonical_encode_decode;
    use libra_prost_ext::test_helpers::assert_protobuf_encode_decode;
    use proptest::collection::vec;

    fn hash_blob(blob: &[u8]) -> HashValue {
        let mut hasher = AccountStateBlobHasher::default();
        hasher.write(blob);
        hasher.finish()
    }

    proptest! {
        #[test]
        fn account_state_blob_proto_roundtrip(account_state_blob in any::<AccountStateBlob>()) {
            assert_protobuf_encode_decode::<crate::proto::types::AccountStateBlob, AccountStateBlob>(&account_state_blob);
        }

        #[test]
        fn account_state_blob_hash(blob in vec(any::<u8>(), 1..100)) {
            prop_assert_eq!(hash_blob(&blob), AccountStateBlob::from(blob).hash());
        }

        #[test]
        fn account_state_with_proof_proto_roundtrip(account_state_with_proof in any::<AccountStateWithProof>()) {
            assert_protobuf_encode_decode::<crate::proto::types::AccountStateWithProof, AccountStateWithProof>(&account_state_with_proof);
        }

        #[test]
        fn account_state_blob_lcs_roundtrip(account_state_blob in any::<AccountStateBlob>()) {
            assert_canonical_encode_decode(account_state_blob);
        }

        #[test]
        fn account_state_with_proof_lcs_roundtrip(account_state_with_proof in any::<AccountStateWithProof>()) {
            assert_canonical_encode_decode(account_state_with_proof);
        }
    }

    #[test]
    fn test_debug_does_not_panic() {
        format!("{:#?}", AccountStateBlob::from(vec![1u8, 2u8, 3u8]));
    }
}
