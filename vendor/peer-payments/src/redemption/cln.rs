//! Local Core Lightning JSON-RPC adapter. Use a dedicated account journal for
//! this service identity across every application sharing its wallet.
use super::*;
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub struct ClnWallet {
    socket: PathBuf,
}
impl ClnWallet {
    pub fn new(socket: impl AsRef<Path>) -> Self {
        Self {
            socket: socket.as_ref().to_owned(),
        }
    }

    pub fn node_info(&self) -> Result<(String, String), Error> {
        let info = self.call("getinfo", json!({}))?;
        let chain = info["network"].as_str().ok_or(Error::Wallet)?;
        let id = info["id"].as_str().ok_or(Error::Wallet)?;
        if !matches!(chain, "bitcoin" | "regtest" | "testnet" | "signet")
            || id.parse::<secp256k1::PublicKey>().is_err()
        {
            return Err(Error::Wallet);
        }
        Ok((chain.into(), id.into()))
    }

    /// Create or recover this exact, local, single-use receiving invoice.
    /// The caller generates a private label unique to its authorized request.
    pub fn receiving_invoice(
        &self,
        label: &str,
        amount_sat: u64,
        now: u64,
    ) -> Result<String, Error> {
        if label.is_empty()
            || label.len() > 128
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._/".contains(&b))
            || amount_sat == 0
        {
            return Err(Error::Invalid("local invoice label or amount"));
        }
        let amount_msat = amount_sat.checked_mul(1000).ok_or(Error::Limit)?;
        let lookup = || -> Result<Option<String>, Error> {
            let response = self.call("listinvoices", json!({"label":label}))?;
            let invoices = response["invoices"].as_array().ok_or(Error::Wallet)?;
            if invoices.is_empty() {
                return Ok(None);
            }
            let [item] = invoices.as_slice() else {
                return Err(Error::Wallet);
            };
            if item["label"] != label
                || item["status"] != "unpaid"
                || msat(&item["amount_msat"])? != amount_msat
            {
                return Err(Error::Conflict);
            }
            let bolt11 = item["bolt11"].as_str().ok_or(Error::Wallet)?;
            // Invoice creation can cross a whole-second boundary during RPC.
            let received_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Error::Wallet)?
                .as_secs();
            let (sat, hash) = invoice_terms(bolt11, now.max(received_at))?;
            if sat != amount_sat || item["payment_hash"] != hash {
                return Err(Error::Wallet);
            }
            Ok(Some(bolt11.into()))
        };
        if let Some(invoice) = lookup()? {
            return Ok(invoice);
        }
        // A response can be lost after the wallet commits, or another creator
        // can win this label. The persisted CLN invoice is authoritative.
        let _ = self.call("invoice", json!({"amount_msat":amount_msat, "label":label, "description":"Service credit cashout", "expiry":600}));
        lookup()?.ok_or(Error::Pending)
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        const MAX_REPLY: usize = 64 * 1024;
        let mut socket = UnixStream::connect(&self.socket)?;
        let timeout = Duration::from_secs(25);
        let deadline = Instant::now() + timeout;
        socket.set_write_timeout(Some(timeout))?;
        let mut req = serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":"peer-credit","method":method,"params":params}),
        )?;
        req.extend_from_slice(b"\n\n");
        socket.write_all(&req)?;
        let mut reply = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            let left = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(Error::Pending)?;
            socket.set_read_timeout(Some(left))?;
            let n = socket.read(&mut chunk)?;
            if n == 0 || reply.len() + n > MAX_REPLY {
                return Err(Error::Wallet);
            }
            reply.extend_from_slice(&chunk[..n]);
            if reply.ends_with(b"\n\n") {
                break;
            }
        }
        let response: Value = serde_json::from_slice(&reply).map_err(|_| Error::Wallet)?;
        if response["id"] != "peer-credit"
            || response["jsonrpc"] != "2.0"
            || response.get("error").is_some()
        {
            return Err(Error::Wallet);
        }
        response.get("result").cloned().ok_or(Error::Wallet)
    }
    fn label(t: &Redemption) -> Result<String, Error> {
        Ok(format!("peer-credit/{}", t.id()?))
    }
}

fn msat(v: &Value) -> Result<u64, Error> {
    v.as_u64()
        .or_else(|| v.as_str()?.strip_suffix("msat")?.parse().ok())
        .ok_or(Error::Wallet)
}
impl RedemptionWallet for ClnWallet {
    fn identity(&mut self, currency: Currency) -> Result<String, Error> {
        let (chain, id) = self.node_info()?;
        if !matches!(
            (currency, chain.as_str()),
            (Currency::Bitcoin, "bitcoin")
                | (Currency::Regtest, "regtest")
                | (Currency::BitcoinTestnet, "testnet")
                | (Currency::Signet, "signet")
        ) {
            return Err(Error::Wallet);
        }
        Ok(format!("{chain}/{id}"))
    }
    fn received(&mut self, t: &Redemption) -> Result<InvoiceState, Error> {
        let response = self.call("listinvoices", json!({"payment_hash":t.payment_hash}))?;
        let [item] = response["invoices"]
            .as_array()
            .ok_or(Error::Wallet)?
            .as_slice()
        else {
            return Err(Error::Wallet);
        };
        let amount = t.amount_sat.checked_mul(1000).ok_or(Error::Limit)?;
        if item["bolt11"] != t.bolt11
            || item["payment_hash"] != t.payment_hash
            || msat(&item["amount_msat"])? != amount
        {
            return Err(Error::Wallet);
        }
        match item["status"].as_str() {
            Some("unpaid") => Ok(InvoiceState::Unpaid),
            Some("paid") if msat(&item["amount_received_msat"])? >= amount => {
                Ok(InvoiceState::Paid {
                    preimage: item["payment_preimage"]
                        .as_str()
                        .ok_or(Error::Wallet)?
                        .into(),
                })
            }
            _ => Err(Error::Wallet),
        }
    }
    fn payment(&mut self, t: &Redemption) -> Result<PaymentState, Error> {
        let response = self.call("listpays", json!({"payment_hash":t.payment_hash}))?;
        let pays = response["pays"].as_array().ok_or(Error::Wallet)?;
        if pays.is_empty() {
            return Ok(PaymentState::Missing);
        }
        let [item] = pays.as_slice() else {
            return Err(Error::Wallet);
        };
        if item["payment_hash"] != t.payment_hash
            || item["bolt11"] != t.bolt11
            || item["label"] != Self::label(t)?
        {
            return Err(Error::Wallet);
        }
        match item["status"].as_str() {
            Some("pending") => Ok(PaymentState::Pending),
            Some("failed") => Ok(PaymentState::Failed),
            Some("complete") => {
                let amount = t.amount_sat.checked_mul(1000).ok_or(Error::Limit)?;
                if msat(&item["amount_msat"])? != amount {
                    return Err(Error::Wallet);
                }
                Ok(PaymentState::Paid {
                    preimage: item["preimage"].as_str().ok_or(Error::Wallet)?.into(),
                    fee_msat: msat(&item["amount_sent_msat"])?
                        .checked_sub(amount)
                        .ok_or(Error::Wallet)?,
                })
            }
            _ => Err(Error::Wallet),
        }
    }
    fn submit(&mut self, t: &Redemption, max_fee_msat: u64) -> Result<(), Error> {
        // Any error after sending might hide a successful payment. Only the
        // exact labeled listpays record can complete the operation.
        self.call(
            "pay",
            json!({"bolt11":t.bolt11,"label":Self::label(t)?,
            "maxfee":max_fee_msat,"retry_for":10}),
        )
        .map(|_| ())
        .map_err(|_| Error::Pending)
    }
}
