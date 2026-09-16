#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PaidExitRatingScore {
    score: i64,
    created_at: u64,
}

fn load_paid_exit_rating_scores(
    path: &Path,
    scope: &str,
    trusted_authors: &HashSet<String>,
) -> Result<HashMap<String, PaidExitRatingScore>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read paid exit ratings {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse paid exit ratings {}", path.display()))?;
    paid_exit_rating_scores_from_value(&value, scope, trusted_authors)
}

fn paid_exit_rating_scores_from_value(
    value: &serde_json::Value,
    scope: &str,
    trusted_authors: &HashSet<String>,
) -> Result<HashMap<String, PaidExitRatingScore>> {
    let mut scores: HashMap<String, PaidExitRatingScore> = HashMap::new();
    for rating in paid_exit_rating_records(value, trusted_authors)? {
        if !paid_exit_rating_matches_scope(&rating, scope) {
            continue;
        }
        let subject = paid_exit_rating_string_field(&rating, "subject")?;
        let rating_value = paid_exit_rating_i64_field(&rating, "rating")?;
        let min_rating = paid_exit_rating_i64_field(&rating, "min_rating")?;
        let max_rating = paid_exit_rating_i64_field(&rating, "max_rating")?;
        let score = paid_exit_normalized_rating_score(rating_value, min_rating, max_rating)?;
        let created_at = paid_exit_rating_u64_field(&rating, "created_at").unwrap_or_default();
        let incoming = PaidExitRatingScore { score, created_at };
        scores
            .entry(subject)
            .and_modify(|existing| {
                if incoming.created_at >= existing.created_at {
                    *existing = incoming;
                }
            })
            .or_insert(incoming);
    }
    Ok(scores)
}

fn merge_paid_exit_rating_scores(
    target: &mut Option<HashMap<String, PaidExitRatingScore>>,
    incoming: HashMap<String, PaidExitRatingScore>,
) {
    if incoming.is_empty() {
        return;
    }
    let target = target.get_or_insert_with(HashMap::new);
    for (subject, incoming_score) in incoming {
        target
            .entry(subject)
            .and_modify(|existing| {
                if incoming_score.created_at >= existing.created_at {
                    *existing = incoming_score;
                }
            })
            .or_insert(incoming_score);
    }
}

fn paid_exit_rating_records(
    value: &serde_json::Value,
    trusted_authors: &HashSet<String>,
) -> Result<Vec<serde_json::Value>> {
    if let Some(records) = value.as_array() {
        return Ok(records
            .iter()
            .filter(|record| paid_exit_rating_record_author_is_trusted(record, trusted_authors))
            .cloned()
            .collect());
    }

    if let Some(records) = value.get("ratings").and_then(|ratings| ratings.as_array()) {
        return Ok(records
            .iter()
            .filter(|record| paid_exit_rating_record_author_is_trusted(record, trusted_authors))
            .cloned()
            .collect());
    }

    if let Some(events) = value.get("events").and_then(|events| events.as_array()) {
        return paid_exit_rating_records_from_events(events, trusted_authors);
    }

    Err(anyhow!(
        "ratings JSON must be an array, an object with a ratings array, or an object with an events array"
    ))
}

fn paid_exit_rating_records_from_events(
    events: &[serde_json::Value],
    trusted_authors: &HashSet<String>,
) -> Result<Vec<serde_json::Value>> {
    let mut records = Vec::new();
    for event_value in events {
        let Ok(event) = paid_exit_verified_rating_fact_event(event_value) else {
            continue;
        };
        if !paid_exit_rating_event_author_is_trusted(&event, trusted_authors) {
            continue;
        }
        if let Ok(record) = paid_exit_rating_record_from_verified_fact_event(&event) {
            records.push(record);
        }
    }
    Ok(records)
}

fn paid_exit_trusted_rating_author_set(authors: &[String]) -> Result<HashSet<String>> {
    let mut normalized = HashSet::new();
    for author in authors.iter().flat_map(|value| value.split(',')) {
        let author = author.trim();
        if author.is_empty() {
            continue;
        }
        normalized.insert(paid_exit_normalize_rating_author(author)?);
    }
    Ok(normalized)
}

fn paid_exit_normalize_rating_author(author: &str) -> Result<String> {
    PublicKey::parse(author.trim())
        .map(|public_key| public_key.to_hex())
        .map_err(|error| anyhow!("invalid trusted rating author {author}: {error}"))
}

fn paid_exit_rating_event_author_is_trusted(
    event: &Event,
    trusted_authors: &HashSet<String>,
) -> bool {
    if trusted_authors.is_empty() {
        return true;
    }
    trusted_authors.contains(&event.pubkey.to_hex())
}

fn paid_exit_rating_record_author_is_trusted(
    record: &serde_json::Value,
    trusted_authors: &HashSet<String>,
) -> bool {
    if trusted_authors.is_empty() {
        return true;
    }
    record
        .get("rater")
        .and_then(|value| value.as_str())
        .and_then(|rater| paid_exit_normalize_rating_author(rater).ok())
        .is_some_and(|author| trusted_authors.contains(&author))
}

fn paid_exit_verified_rating_fact_event(event_value: &serde_json::Value) -> Result<Event> {
    let event: Event = serde_json::from_value(event_value.clone())
        .context("rating fact event is not valid Nostr event JSON")?;
    event
        .verify()
        .map_err(|error| anyhow!("rating fact event verification failed: {error}"))?;
    if event.kind != Kind::Custom(RATING_FACT_KIND as u16) {
        return Err(anyhow!(
            "rating fact event kind must be {RATING_FACT_KIND}, got {:?}",
            event.kind
        ));
    }
    Ok(event)
}

fn paid_exit_rating_record_from_verified_fact_event(event: &Event) -> Result<serde_json::Value> {
    let rating = nostr_social_memory::rating_from_event(event)?;
    if rating.scope.as_deref() == Some("vpn.exit")
        && PublicKey::parse(&rating.rater)? != event.pubkey
    {
        return Err(anyhow!("exit rating author does not match its signer"));
    }
    Ok(serde_json::to_value(rating)?)
}

#[cfg(test)]
fn paid_exit_fact_optional_scalar(event_value: &serde_json::Value, key: &str) -> Option<String> {
    paid_exit_fact_values(event_value, key).into_iter().next()
}

#[cfg(test)]
fn paid_exit_fact_values(event_value: &serde_json::Value, key: &str) -> Vec<String> {
    paid_exit_fact_tags(event_value)
        .into_iter()
        .filter_map(|tag| {
            let parts = tag.as_array()?;
            if parts.first().and_then(|value| value.as_str()) != Some(key) {
                return None;
            }
            parts.get(1).and_then(|value| value.as_str()).map(str::trim)
        })
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
fn paid_exit_fact_tags(event_value: &serde_json::Value) -> Vec<&serde_json::Value> {
    event_value
        .get("tags")
        .and_then(|tags| tags.as_array())
        .map(|tags| tags.iter().collect())
        .unwrap_or_default()
}

fn paid_exit_rating_matches_scope(rating: &serde_json::Value, expected_scope: &str) -> bool {
    let expected_scope = expected_scope.trim();
    expected_scope.is_empty()
        || rating
            .get("scope")
            .and_then(|value| value.as_str())
            .is_some_and(|scope| scope.trim() == expected_scope)
}

#[cfg(test)]
fn paid_exit_rating_fact_matches_scope(
    event_value: &serde_json::Value,
    expected_scope: &str,
) -> bool {
    let expected_scope = expected_scope.trim();
    expected_scope.is_empty()
        || paid_exit_fact_optional_scalar(event_value, "scope")
            .is_some_and(|scope| scope.trim() == expected_scope)
}

fn paid_exit_rating_string_field(rating: &serde_json::Value, key: &str) -> Result<String> {
    rating
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("rating record is missing string field {key}"))
}

fn paid_exit_rating_i64_field(rating: &serde_json::Value, key: &str) -> Result<i64> {
    rating
        .get(key)
        .and_then(|value| value.as_i64())
        .ok_or_else(|| anyhow!("rating record is missing integer field {key}"))
}

fn paid_exit_rating_u64_field(rating: &serde_json::Value, key: &str) -> Option<u64> {
    rating.get(key).and_then(|value| value.as_u64())
}

fn paid_exit_normalized_rating_score(rating: i64, min_rating: i64, max_rating: i64) -> Result<i64> {
    if min_rating >= max_rating {
        return Err(anyhow!("invalid rating range {min_rating}..{max_rating}"));
    }
    if rating < min_rating || rating > max_rating {
        return Err(anyhow!(
            "rating {rating} outside range {min_rating}..{max_rating}"
        ));
    }
    let rating = i128::from(rating);
    let min = i128::from(min_rating);
    let max = i128::from(max_rating);
    let width = max - min;
    let centered = rating.saturating_mul(2) - min - max;
    Ok(((centered.saturating_mul(100)) / width) as i64)
}

fn paid_exit_sort_offers_by_rating(
    offers: &mut [SignedPaidRouteOffer],
    rating_scores: &HashMap<String, PaidExitRatingScore>,
) {
    offers.sort_by(|left, right| {
        let left_score =
            paid_exit_signed_offer_rating_score(left, rating_scores).map_or(0, |score| score.score);
        let right_score = paid_exit_signed_offer_rating_score(right, rating_scores)
            .map_or(0, |score| score.score);
        right_score
            .cmp(&left_score)
            .then_with(|| {
                right
                    .event
                    .created_at
                    .as_secs()
                    .cmp(&left.event.created_at.as_secs())
            })
            .then_with(|| left.event.id.to_string().cmp(&right.event.id.to_string()))
    });
}

fn paid_exit_signed_offer_rating_score(
    signed: &SignedPaidRouteOffer,
    rating_scores: &HashMap<String, PaidExitRatingScore>,
) -> Option<PaidExitRatingScore> {
    signed
        .offer()
        .ok()
        .and_then(|offer| rating_scores.get(&offer.seller_npub).copied())
}

#[cfg(test)]
fn paid_exit_rating_fact_filter(limit: usize, since_unix: Option<u64>, scope: &str) -> Filter {
    let mut filter = Filter::new().kind(Kind::Custom(RATING_FACT_KIND as u16));
    if limit > 0 {
        filter = filter.limit(limit);
    }
    if let Some(since_unix) = since_unix {
        filter = filter.since(Timestamp::from(since_unix));
    }
    let scope = scope.trim();
    if !scope.is_empty() {
        filter = filter.custom_tag(
            SingleLetterTag::lowercase(Alphabet::I),
            scope.to_lowercase(),
        );
    }
    filter
}

fn paid_exit_offer_results_json(
    offers: &[SignedPaidRouteOffer],
    rating_scores: Option<&HashMap<String, PaidExitRatingScore>>,
) -> Result<Vec<serde_json::Value>> {
    offers
        .iter()
        .map(|signed| {
            let offer: PaidRouteOffer = signed.offer()?;
            let rating_score = rating_scores
                .and_then(|scores| scores.get(&offer.seller_npub))
                .map(|score| score.score);
            let mut value = json!({
                "event_id": signed.event.id.to_string(),
                "created_at": signed.event.created_at.as_secs(),
                "offer": offer,
            });
            if rating_scores.is_some() {
                value["rating_score"] = rating_score
                    .map(|score| json!(score))
                    .unwrap_or(serde_json::Value::Null);
            }
            Ok(value)
        })
        .collect()
}
