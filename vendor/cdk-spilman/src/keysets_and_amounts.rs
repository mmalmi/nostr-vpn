//! Keyset Information
//!
//! Contains keyset-related types and fee calculation functions.

use serde::{Deserialize, Serialize};

use cashu::nuts::{CurrencyUnit, Id, Keys};

/// Result of inverse_deterministic_value_after_fees
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InverseFeeResult {
    /* Certain post-fee balances are impossible, if there are non-zero fees,
     * in this deterministic system. So even if we intend the post-fee
     * balance to be 100 sats, it may need to be 101 sats (actual_balance)
     * and the pre-fee amount may need to be larger, e.g. 104 sats (nominal).
     * So the funding token it swapped to created 104 sats of P2PK commitment
     * outputs to Charlie, which become 101 sats after he swaps them into his
     * own wallet
     */
    /// The nominal value to allocate in deterministic outputs
    pub nominal_value: u64,
    /// The actual balance after fees (may be >= target due to discrete amounts)
    pub actual_balance: u64,
}

/// An ordered list of amounts that sum to a target value
///
/// Created by the greedy algorithm in from_target.
/// The amounts are stored in a BTreeMap (sorted by the amount).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedListOfAmounts {
    amounts: Vec<u64>,
    /// Map from amount to count, for iteration/inspection
    pub count_by_amount: std::collections::BTreeMap<u64, usize>,
    /// Input fee in parts per thousand (from keyset)
    input_fee_ppk: u64,
}

impl OrderedListOfAmounts {
    /// Create amounts to reach a target value using keyset info
    ///
    /// Uses a largest-first greedy algorithm to minimize the number of outputs.
    /// Only considers amounts <= maximum_amount from the keyset.
    /// If maximum_amount is 0, no limit is applied (uses all keyset denominations).
    pub fn from_target(
        target: u64,
        maximum_amount: u64,
        keyset_info: &KeysetInfo,
    ) -> anyhow::Result<Self> {
        use std::collections::BTreeMap;

        let mut count_by_amount = BTreeMap::new();

        if target == 0 {
            return Ok(Self {
                amounts: Vec::new(),
                count_by_amount,
                input_fee_ppk: keyset_info.input_fee_ppk,
            });
        }

        let mut remaining = target;

        // Greedy algorithm: use largest amounts first to minimize number of outputs
        // keyset_info.amounts_largest_first is already sorted descending
        for &amount in &keyset_info.amounts_largest_first {
            if maximum_amount > 0 && amount > maximum_amount {
                continue;
            }
            let mut count = 0;
            while remaining >= amount {
                remaining -= amount;
                count += 1;
            }
            if count > 0 {
                count_by_amount.insert(amount, count);
            }
        }

        if remaining != 0 {
            if maximum_amount == 0 {
                anyhow::bail!("Cannot represent {} using available amounts", target);
            } else {
                anyhow::bail!(
                    "Cannot represent {} using available amounts (max {})",
                    target,
                    maximum_amount
                );
            }
        }

        // Build amounts vector by iterating in reverse (largest-first)
        let mut amounts = Vec::new();
        for (&amount, &count) in count_by_amount.iter().rev() {
            for _ in 0..count {
                amounts.push(amount);
            }
        }

        Ok(Self {
            amounts,
            count_by_amount,
            input_fee_ppk: keyset_info.input_fee_ppk,
        })
    }

    /// Get the number of amounts in the list
    pub fn len(&self) -> usize {
        self.amounts.len()
    }

    /// Check if the list is empty
    pub fn is_empty(&self) -> bool {
        self.amounts.is_empty()
    }

    /// Get the total nominal value (sum of all amounts)
    pub fn nominal_total(&self) -> u64 {
        self.amounts.iter().sum()
    }

    /// Calculate the total amount (alias for nominal_total)
    pub fn total_amount(&self) -> u64 {
        self.nominal_total()
    }

    /// Calculate the value after fees
    ///
    /// Uses the fee formula: ceil(nominal * ppk / 1000)
    pub fn value_after_fees(&self) -> u64 {
        let total = self.nominal_total();
        if self.input_fee_ppk == 0 {
            return total;
        }
        let num_outputs = self.amounts.len() as u64;
        let fee = (self.input_fee_ppk * num_outputs).div_ceil(1000);
        total.saturating_sub(fee)
    }

    /// Iterate over the count map in normal order (smallest-first)
    /// Returns an iterator over (&amount, &count) pairs in ascending order by amount
    /// This is the recommended order for Cashu protocol outputs
    pub fn iter_smallest_first(&self) -> impl Iterator<Item = (&u64, &usize)> {
        self.count_by_amount.iter()
    }

    /// Get the individual amounts
    pub fn amounts(&self) -> &[u64] {
        &self.amounts
    }
}

/// Keyset information for fee calculations and amount selection
///
/// Represents a real keyset from a mint. The keys and amounts are not filtered;
/// methods that need to respect a maximum amount take it as a parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeysetInfo {
    /// Keyset ID
    pub keyset_id: Id,
    /// Keyset unit
    pub unit: CurrencyUnit,
    /// Set of active keys from the mint (map from amount to pubkey)
    #[serde(rename = "keys")]
    pub active_keys: Keys,
    /// Available amounts in the keyset, sorted largest first
    #[serde(rename = "amounts")]
    pub amounts_largest_first: Vec<u64>,
    /// Input fee in parts per thousand
    pub input_fee_ppk: u64,
    /// Final expiry of the keyset
    pub final_expiry: Option<u64>,
}

impl KeysetInfo {
    /// Create new keyset info from active keys
    pub fn new(
        keyset_id: Id,
        unit: CurrencyUnit,
        active_keys: Keys,
        input_fee_ppk: u64,
        final_expiry: Option<u64>,
    ) -> Self {
        // Extract and sort amounts from the keyset (largest first)
        let mut amounts_largest_first: Vec<u64> =
            active_keys.iter().map(|(amt, _)| u64::from(*amt)).collect();
        amounts_largest_first.sort_unstable_by(|a, b| b.cmp(a)); // Descending order

        Self {
            keyset_id,
            unit,
            active_keys,
            amounts_largest_first,
            input_fee_ppk,
            final_expiry,
        }
    }

    /// Calculate the value after fees for a given nominal value
    ///
    /// Given a nominal value (what you allocate in deterministic outputs),
    /// this calculates what remains after paying the input fees when those outputs are used.
    /// Only considers amounts <= maximum_amount when determining output count.
    pub fn deterministic_value_after_fees(
        &self,
        nominal_value: u64,
        maximum_amount: u64,
    ) -> anyhow::Result<u64> {
        let amounts = OrderedListOfAmounts::from_target(nominal_value, maximum_amount, self)?;
        Ok(amounts.value_after_fees())
    }

    /// Find the inverse of deterministic_value_after_fees
    ///
    /// Given a target final balance, this returns the smallest nominal value
    /// that achieves at least the target balance, along with the actual balance
    /// you'll get (which may be slightly higher due to discrete denominations).
    /// Only considers amounts <= maximum_amount.
    pub fn inverse_deterministic_value_after_fees(
        &self,
        target_balance: u64,
        maximum_amount: u64,
    ) -> anyhow::Result<InverseFeeResult> {
        if target_balance == 0 {
            return Ok(InverseFeeResult {
                nominal_value: 0,
                actual_balance: 0,
            });
        }

        // If there are no fees, the inverse is trivial
        if self.input_fee_ppk == 0 {
            return Ok(InverseFeeResult {
                nominal_value: target_balance,
                actual_balance: target_balance,
            });
        }

        // Start with the target as initial guess and search upward.
        // Convergence is guaranteed: with fee_ppk < 1000, fee per output < 1,
        // and output count grows logarithmically for power-of-2 denominations,
        // so value_after_fees(N) grows faster than fees as N increases.
        let mut nominal = target_balance;

        loop {
            let actual_balance = self.deterministic_value_after_fees(nominal, maximum_amount)?;

            if actual_balance >= target_balance {
                return Ok(InverseFeeResult {
                    nominal_value: nominal,
                    actual_balance,
                });
            }

            nominal += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cashu::Amount;
    use std::str::FromStr;

    // Helper to create a simple KeysetInfo for testing
    fn mock_keyset_info(amounts: Vec<u64>, input_fee_ppk: u64) -> KeysetInfo {
        use cashu::nuts::{Id, Keys, PublicKey};
        use std::collections::BTreeMap;

        // Create dummy keys map
        let mut keys_map = BTreeMap::new();
        let dummy_pubkey = PublicKey::from_str(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
        )
        .unwrap();
        for &amt in &amounts {
            keys_map.insert(Amount::from(amt), dummy_pubkey);
        }

        let mut amounts_largest_first = amounts;
        amounts_largest_first.sort_by(|a, b| b.cmp(a));

        let active_keys = Keys::new(keys_map);
        let keyset_id = Id::v1_from_keys(&active_keys);

        KeysetInfo::new(
            keyset_id,
            CurrencyUnit::Sat,
            active_keys,
            input_fee_ppk,
            None,
        )
    }

    #[test]
    fn test_from_target_max_1_count_equals_amount() {
        let maximum_amount_for_one_output = 1;
        let keyset = mock_keyset_info(vec![1, 2, 4, 8, 16], 0);

        for target in 1..=20 {
            let result =
                OrderedListOfAmounts::from_target(target, maximum_amount_for_one_output, &keyset)
                    .unwrap();
            assert_eq!(
                result.len(),
                target as usize,
                "target={}: expected {} outputs, got {}",
                target,
                target,
                result.len()
            );
            assert_eq!(result.nominal_total(), target);
        }
    }

    #[test]
    fn test_from_target_max_2_even_targets() {
        let maximum_amount_for_one_output = 2;
        let keyset = mock_keyset_info(vec![1, 2, 4, 8, 16], 0);

        for target in (2..=20).step_by(2) {
            let result =
                OrderedListOfAmounts::from_target(target, maximum_amount_for_one_output, &keyset)
                    .unwrap();
            assert_eq!(
                result.len(),
                (target / 2) as usize,
                "target={}: expected {} outputs, got {}",
                target,
                target / 2,
                result.len()
            );
            assert_eq!(result.nominal_total(), target);
        }
    }

    #[test]
    fn test_from_target_max_0_means_no_limit() {
        let keyset = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024], 0);
        let result = OrderedListOfAmounts::from_target(1000, 0, &keyset).unwrap();
        assert_eq!(result.nominal_total(), 1000);
        assert!(result.len() < 20);

        let result_limited = OrderedListOfAmounts::from_target(1000, 64, &keyset).unwrap();
        assert!(result.len() < result_limited.len());
    }

    #[test]
    fn test_from_target_powers_of_2() {
        let keyset = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 0);
        let result = OrderedListOfAmounts::from_target(7, 64, &keyset).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result.nominal_total(), 7);
    }

    #[test]
    fn test_from_target_zero() {
        let keyset = mock_keyset_info(vec![1, 2, 4], 0);
        let result = OrderedListOfAmounts::from_target(0, 4, &keyset).unwrap();
        assert_eq!(result.len(), 0);
        assert_eq!(result.nominal_total(), 0);
    }

    #[test]
    fn test_roundtrip_property_zero_fees() {
        let keyset = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 0);
        let max_amount = 64;

        for target in 0..=100 {
            let inverse_result = keyset
                .inverse_deterministic_value_after_fees(target, max_amount)
                .unwrap();

            assert_eq!(inverse_result.nominal_value, target);
            assert_eq!(inverse_result.actual_balance, target);
        }
    }
}
