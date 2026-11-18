//! Conditional discharge of completed, issuer-specific service debt.
use crate::{protocol::identifier, Error, Signed, WireMessage};
use lightning_invoice::{Bolt11Invoice, Currency};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(unix)]
mod cln;
mod control;
#[cfg(unix)]
pub use cln::ClnWallet;

pub const MAX_DEPTH: u8 = 4;
const MAX_INVOICE: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redemption {
    pub creditor: String,
    pub debtor: String,
    pub agreement_id: String,
    pub agreement_commitment: String,
    pub previous_sat: u64,
    pub amount_sat: u64,
    pub bolt11: String,
    pub payment_hash: String,
    pub parent: Option<String>,
    pub depth: u8,
    /// Cumulative conversion charge in creditor's service credit above the
    /// Lightning output. Omitted at par to preserve existing signatures.
    #[serde(default, skip_serializing_if = "zero")]
    pub fee_sat: u64,
}

fn zero(amount: &u64) -> bool {
    *amount == 0
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ConversionEarnings {
    pub forwarding_fee_sat: u64,
    pub terminal_fee_sat: u64,
    pub network_fee_msat: u64,
}

impl Redemption {
    pub fn debit_sat(&self) -> Result<u64, Error> {
        self.amount_sat
            .checked_add(self.fee_sat)
            .ok_or(Error::Limit)
    }
    pub fn verify(signed: &Signed<Self>, now: u64) -> Result<(), Error> {
        signed.payload.validate()?;
        crate::protocol::authenticate(
            &crate::SchnorrVerifier,
            &signed.payload.creditor,
            WireMessage::Redemption(signed.payload.clone()),
            &signed.signature,
        )?;
        signed.payload.validate_invoice(now)?;
        Ok(())
    }

    pub fn id(&self) -> Result<String, Error> {
        Ok(format!(
            "{:x}",
            Sha256::digest(WireMessage::Redemption(self.clone()).signing_bytes()?)
        ))
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        identifier(&self.agreement_id)?;
        self.debit_sat()?;
        if self.creditor == self.debtor
            || self.depth == 0
            || self.depth > MAX_DEPTH
            || (self.depth == 1) != self.parent.is_none()
            || self.parent.as_ref().is_some_and(|p| !hash_hex(p))
            || !hash_hex(&self.creditor)
            || !hash_hex(&self.debtor)
            || !hash_hex(&self.agreement_commitment)
            || !hash_hex(&self.payment_hash)
            || self.bolt11.len() > MAX_INVOICE
            || self.amount_sat == 0
        {
            return Err(Error::Invalid("redemption terms"));
        }
        Ok(())
    }

    fn validate_invoice(&self, now: u64) -> Result<Currency, Error> {
        self.validate()?;
        let invoice = parse_invoice(&self.bolt11, now)?;
        if invoice.amount_milli_satoshis()
            != Some(self.amount_sat.checked_mul(1000).ok_or(Error::Limit)?)
            || invoice.payment_hash().to_string() != self.payment_hash
        {
            return Err(Error::Invalid("invoice terms"));
        }
        Ok(invoice.currency())
    }
}

pub(crate) fn hash_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn decode_invoice(s: &str) -> Result<Bolt11Invoice, Error> {
    if s.len() > MAX_INVOICE || !s.starts_with("ln") {
        return Err(Error::Invalid("BOLT11 invoice"));
    }
    let invoice: Bolt11Invoice = s.parse().map_err(|_| Error::Invalid("BOLT11 invoice"))?;
    let msat = invoice
        .amount_milli_satoshis()
        .ok_or(Error::Invalid("fixed amount required"))?;
    if msat == 0 || msat % 1000 != 0 {
        return Err(Error::Invalid("whole sat amount required"));
    }
    Ok(invoice)
}

fn parse_invoice(s: &str, now: u64) -> Result<Bolt11Invoice, Error> {
    let invoice = decode_invoice(s)?;
    if invoice.duration_since_epoch().as_secs() > now
        || invoice.expires_at().ok_or(Error::Limit)?.as_secs() <= now
    {
        return Err(Error::Expired);
    }
    Ok(invoice)
}

pub fn invoice_terms(bolt11: &str, now: u64) -> Result<(u64, String), Error> {
    let invoice = parse_invoice(bolt11, now)?;
    Ok((
        invoice
            .amount_milli_satoshis()
            .ok_or(Error::Invalid("invoice amount"))?
            / 1000,
        invoice.payment_hash().to_string(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedemptionProof {
    pub request_id: String,
    pub payment_hash: String,
    pub preimage: String,
}

impl RedemptionProof {
    pub(crate) fn check(&self, terms: &Redemption) -> Result<(), Error> {
        if self.request_id != terms.id()?
            || self.payment_hash != terms.payment_hash
            || !hash_hex(&self.preimage)
        {
            return Err(Error::Authentication);
        }
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&self.preimage[i * 2..i * 2 + 2], 16)
                .map_err(|_| Error::Authentication)?;
        }
        if format!("{:x}", Sha256::digest(bytes)) != self.payment_hash {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}

/// Supply from the local request/policy, independently of remote JSON.
pub struct RedemptionApproval {
    pub creditor: String,
    pub agreement_id: String,
    pub payment_hash: String,
    pub max_amount_sat: u64,
    pub max_fee_msat: u64,
    pub max_lifetime_payout_sat: u64,
    pub max_lifetime_fees_msat: u64,
}
impl RedemptionApproval {
    fn check_binding(&self, terms: &Redemption) -> Result<(), Error> {
        if self.creditor != terms.creditor
            || self.agreement_id != terms.agreement_id
            || self.payment_hash != terms.payment_hash
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    fn check(&self, terms: &Redemption) -> Result<(), Error> {
        self.check_binding(terms)?;
        if terms.amount_sat > self.max_amount_sat {
            return Err(Error::Limit);
        }
        Ok(())
    }
}

/// A trusted local wallet adapter. The identity must distinguish networks and
/// wallets. Outgoing lookups must bind the exact request label as well as invoice.
pub trait RedemptionWallet {
    fn identity(&mut self, currency: Currency) -> Result<String, Error>;
    fn received(&mut self, terms: &Redemption) -> Result<InvoiceState, Error>;
    fn payment(&mut self, terms: &Redemption) -> Result<PaymentState, Error>;
    fn submit(&mut self, terms: &Redemption, max_fee_msat: u64) -> Result<(), Error>;
}

pub enum InvoiceState {
    Unpaid,
    Paid { preimage: String },
}
pub enum PaymentState {
    Missing,
    Pending,
    Failed,
    Paid { preimage: String, fee_msat: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Role {
    Holder {
        outgoing: Redemption,
        wallet: Option<String>,
    },
    Payer {
        incoming: Signed<Redemption>,
        wallet: String,
        max_fee_msat: u64,
    },
    Forward {
        incoming: Signed<Redemption>,
        outgoing: Redemption,
    },
}
impl Role {
    pub(super) fn incoming(&self) -> Option<&Signed<Redemption>> {
        match self {
            Self::Payer { incoming, .. } | Self::Forward { incoming, .. } => Some(incoming),
            _ => None,
        }
    }
    pub(super) fn outgoing(&self) -> Option<&Redemption> {
        match self {
            Self::Holder { outgoing, .. } | Self::Forward { outgoing, .. } => Some(outgoing),
            _ => None,
        }
    }
    pub(super) fn legs(&self) -> impl Iterator<Item = &Redemption> {
        self.incoming()
            .map(|s| &s.payload)
            .into_iter()
            .chain(self.outgoing())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub role: Role,
    pub done: Option<Completion>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Completion {
    pub preimage: String,
    pub fee_msat: u64,
    pub downstream_signature: Option<String>,
}
