use crate::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const WIRE_VERSION: u16 = 1;
pub const MAX_WIRE_BYTES: usize = 16 * 1024;
const DOMAIN: &str = "peer-payments/v1";

/// Identity adapters must verify against the exact expected identity. Neither
/// a claimed packet source nor a Nostr follow is signature verification.
pub trait Verifier {
    fn verify(&self, identity: &str, message: &[u8], signature: &str) -> bool;
}

/// Both peers sign the same immutable agreement. `resource` binds authorization
/// to the application's route, object/lease, or other service scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agreement {
    pub id: String,
    pub payer: String,
    pub provider: String,
    pub service: String,
    pub resource: String,
    pub max_units: u64,
    pub price_sat: u64,
    pub price_per_units: u64,
    pub max_amount_sat: u64,
    pub created_at: u64,
    pub expires_at: u64,
}

impl Agreement {
    pub fn commitment(&self) -> Result<String, Error> {
        let digest = Sha256::digest(WireMessage::Agreement(self.clone()).signing_bytes()?);
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }
    pub fn amount_for(&self, units: u64) -> Result<u64, Error> {
        if self.price_per_units == 0 || units > self.max_units {
            return Err(Error::Invalid("service units"));
        }
        u64::try_from(
            (u128::from(units) * u128::from(self.price_sat))
                .div_ceil(u128::from(self.price_per_units)),
        )
        .map_err(|_| Error::Invalid("amount overflow"))
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        for value in [
            &self.id,
            &self.payer,
            &self.provider,
            &self.service,
            &self.resource,
        ] {
            identifier(value)?;
        }
        if self.payer == self.provider
            || self.max_units == 0
            || self.price_sat == 0
            || self.max_amount_sat == 0
            || self.created_at >= self.expires_at
            || self.amount_for(self.max_units)? != self.max_amount_sat
        {
            return Err(Error::Invalid("agreement terms"));
        }
        Ok(())
    }
}

/// The payer signs cumulative *application-verified* useful service. The
/// provider checks its own meter before applying it. Closing is immutable;
/// timeout alone is not a close, refund, or proof of non-delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub agreement_id: String,
    pub agreement_commitment: String,
    pub payer: String,
    pub provider: String,
    pub cumulative_units: u64,
    pub final_receipt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub payload: T,
    pub signature: String,
}

/// Equal cancellation of two opposite, completed service debts. Parties are
/// ordered lexicographically; each sale is identified by its full commitment.
/// Previous cumulative offsets prevent using the same debt in two settlements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Netting {
    pub id: String,
    pub left: String,
    pub right: String,
    pub left_sale: String,
    pub left_commitment: String,
    pub left_previous_sat: u64,
    pub right_sale: String,
    pub right_commitment: String,
    pub right_previous_sat: u64,
    pub amount_sat: u64,
}

/// Fixed tagged envelope, separate from FIPS wire records and Cashu messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum WireMessage {
    Agreement(Agreement),
    Receipt(Receipt),
    Netting(Netting),
}

impl WireMessage {
    /// Decode only a bounded, versioned control message. Transport adapters must
    /// also cap frame length before buffering it and authenticate the session.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(Error::Limit);
        }
        let (domain, version, message): (String, u16, Self) = serde_json::from_slice(bytes)?;
        if domain != DOMAIN || version != WIRE_VERSION {
            return Err(Error::Invalid("wire version"));
        }
        Ok(message)
    }

    /// The versioned signing contract is the UTF-8 JSON array
    /// `["peer-payments/v1",1,<tagged record>]`, in this schema's field order.
    /// Do not sign arbitrary JSON spellings or an account snapshot.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        let bytes = serde_json::to_vec(&(DOMAIN, WIRE_VERSION, self))?;
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(Error::Limit);
        }
        Ok(bytes)
    }
}

pub(crate) fn authenticate(
    verifier: &impl Verifier,
    identity: &str,
    message: WireMessage,
    signature: &str,
) -> Result<(), Error> {
    if signature.is_empty()
        || signature.len() > 512
        || !verifier.verify(identity, &message.signing_bytes()?, signature)
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

pub(crate) fn identifier(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(Error::Invalid("identifier"));
    }
    Ok(())
}
