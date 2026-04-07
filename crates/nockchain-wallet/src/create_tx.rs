use wallet_tx_builder::types::CandidateNote;

use super::*;

pub(crate) fn ensure_manual_planner_parity(
    requested_names: &[Name],
    planned_names: &[Name],
) -> Result<(), String> {
    let mut normalized_requested = requested_names
        .iter()
        .map(|name| (name.first.to_array(), name.last.to_array()))
        .collect::<Vec<_>>();
    let mut normalized_planned = planned_names
        .iter()
        .map(|name| (name.first.to_array(), name.last.to_array()))
        .collect::<Vec<_>>();
    normalized_requested.sort_unstable();
    normalized_planned.sort_unstable();

    if normalized_planned != normalized_requested {
        let planned_names_arg = Wallet::format_note_names_for_create_tx(planned_names);
        let requested_names_arg = Wallet::format_note_names_for_create_tx(requested_names);
        return Err(format!(
            "planner parity mismatch: selected names differ from user-provided manual names (planned='{}', requested='{}')",
            planned_names_arg, requested_names_arg
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
/// Subset of chain note-data constants consumed by planner fee logic.
pub(crate) struct PlannerNoteDataConstantsNoun {
    pub(crate) _max_size: u64,
    pub(crate) min_fee: u64,
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
/// Blockchain constants payload extracted from wallet state for planning.
pub(crate) struct PlannerBlockchainConstantsNoun {
    pub(crate) _v1_phase: u64,
    pub(crate) bythos_phase: u64,
    pub(crate) data: PlannerNoteDataConstantsNoun,
    pub(crate) base_fee: u64,
    pub(crate) input_fee_divisor: u64,
    pub(crate) _legacy_constants: Noun,
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
/// Embedded v0 constants payload carried inside wallet blockchain constants.
struct PlannerV0BlockchainConstantsNoun {
    _max_block_size: Noun,
    _blocks_per_epoch: Noun,
    _target_epoch_duration: Noun,
    _update_candidate_timestamp_interval: Noun,
    _max_future_timestamp: Noun,
    _min_past_blocks: Noun,
    _genesis_target_atom: Noun,
    _max_target_atom: Noun,
    _check_pow_flag: bool,
    coinbase_timelock_min: u64,
    _pow_len: Noun,
    _max_coinbase_split: Noun,
    _first_month_coinbase_min: Noun,
}

impl PlannerBlockchainConstantsNoun {
    /// Returns the consensus coinbase relative timelock minimum.
    pub(crate) fn coinbase_timelock_min(&self) -> Result<u64, NockAppError> {
        let parsed = PlannerV0BlockchainConstantsNoun::from_noun(&self._legacy_constants).map_err(
            |err| {
                NockAppError::OtherError(format!(
                    "wallet blockchain-constants payload missing coinbase timelock min: {err}"
                ))
            },
        )?;
        Ok(parsed.coinbase_timelock_min)
    }
}

#[derive(Debug, Clone, Default)]
/// Lock matcher for simple single-signer PKH lock resolution.
///
/// This matcher is intentionally scoped to single-signer PKH spend conditions
/// that can be satisfied by locally held signer keys.
/// Multisig or otherwise complex lock forms are intentionally not matched here.
pub(crate) struct SigningKeyLockMatcher {
    signer_pkhs: std::collections::BTreeSet<[u64; 5]>,
}

impl SigningKeyLockMatcher {
    /// Builds a matcher from signer pubkey-hashes.
    pub(crate) fn from_signer_keys(signer_keys: &[Hash]) -> Self {
        let signer_pkhs = signer_keys
            .iter()
            .map(Hash::to_array)
            .collect::<std::collections::BTreeSet<_>>();
        Self { signer_pkhs }
    }
}

impl LockMatcher for SigningKeyLockMatcher {
    fn matches(&self, note_first_name: &Hash, spend_condition: &SpendCondition) -> bool {
        let mut primitive_count = 0usize;
        let mut tim_primitive_count = 0usize;
        let mut signer_pkh_primitive = None;
        for primitive in spend_condition.iter() {
            primitive_count = primitive_count.saturating_add(1);
            match primitive {
                LockPrimitive::Pkh(pkh) => {
                    if signer_pkh_primitive.is_some() {
                        return false;
                    }
                    signer_pkh_primitive = Some(pkh);
                }
                LockPrimitive::Tim(_) => {
                    tim_primitive_count = tim_primitive_count.saturating_add(1);
                }
                _ => return false,
            }
        }
        let Some(pkh) = signer_pkh_primitive else {
            return false;
        };
        if pkh.m != 1 || pkh.hashes.len() != 1 {
            return false;
        }
        let Some(hash) = pkh.hashes.first() else {
            return false;
        };
        if !self.signer_pkhs.contains(&hash.to_array()) {
            return false;
        }
        let is_simple_shape = tim_primitive_count == 0 && primitive_count == 1;
        let is_coinbase_shape = tim_primitive_count == 1 && primitive_count == 2;
        if !is_simple_shape && !is_coinbase_shape {
            return false;
        }
        let Ok(reconstructed_first_name) = spend_condition.first_name() else {
            return false;
        };
        note_first_name.to_array() == reconstructed_first_name.as_hash().to_array()
    }
}

impl Wallet {
    fn parse_note_names_as_hashes(raw: &str) -> Result<Vec<Name>, NockAppError> {
        Self::parse_note_names(raw)?
            .into_iter()
            .map(|(first, last)| {
                let first_hash = Hash::from_base58(&first).map_err(|err| {
                    NockAppError::from(CrownError::Unknown(format!(
                        "Invalid note first-name hash '{}': {}",
                        first, err
                    )))
                })?;
                let last_hash = Hash::from_base58(&last).map_err(|err| {
                    NockAppError::from(CrownError::Unknown(format!(
                        "Invalid note last-name hash '{}': {}",
                        last, err
                    )))
                })?;
                Ok(Name::new(first_hash, last_hash))
            })
            .collect()
    }

    /// Formats selected names into the canonical create-tx `--names` argument.
    fn format_note_names_for_create_tx(names: &[Name]) -> String {
        names
            .iter()
            .map(|name| format!("[{} {}]", name.first.to_base58(), name.last.to_base58()))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Determines whether a manual note set is all-v1 or all-v0.
    /// Missing notes are ignored here so planner manual-mode errors can report them.
    fn manual_candidate_version_policy(
        note_names: &[Name],
        candidates: &[CandidateNote],
    ) -> Result<CandidateVersionPolicy, String> {
        if note_names.is_empty() {
            return Err("manual mode requires at least one note name".to_string());
        }

        let mut found_v0 = false;
        let mut found_v1 = false;

        for name in note_names {
            let Some(candidate) = candidates
                .iter()
                .find(|candidate| candidate.identity().name == *name)
            else {
                return Err(format!(
                    "manual mode references unknown note {}/{}",
                    name.first.to_base58(),
                    name.last.to_base58()
                ));
            };

            match candidate.version() {
                nockchain_types::tx_engine::common::Version::V0 => found_v0 = true,
                _ => found_v1 = true,
            }
        }

        match (found_v0, found_v1) {
            (true, false) => Ok(CandidateVersionPolicy::V0Only),
            (false, true) => Ok(CandidateVersionPolicy::V1Only),
            (false, false) => Err("manual mode requires at least one note name".to_string()),
            (true, true) => Err(
                "manual create-tx cannot mix v0 and v1 notes; select notes from only one version"
                    .to_string(),
            ),
        }
    }

    /// Maps CLI ordering strategy onto planner selection order semantics.
    fn planner_order_direction(strategy: NoteSelectionStrategyCli) -> SelectionOrder {
        match strategy {
            NoteSelectionStrategyCli::Ascending => SelectionOrder::Ascending,
            NoteSelectionStrategyCli::Descending => SelectionOrder::Descending,
        }
    }

    /// Reads the latest synced balance snapshot from wallet state.
    async fn peek_balance_state(&mut self) -> Result<v1::BalanceUpdate, NockAppError> {
        let mut slab = NounSlab::new();
        let balance_tag = make_tas(&mut slab, "balance").as_noun();
        let path = T(&mut slab, &[balance_tag, SIG]);
        slab.set_root(path);

        let result = self.app.peek(slab).await?;
        let maybe_balance: Option<Option<v1::BalanceUpdate>> =
            unsafe { <Option<Option<v1::BalanceUpdate>>>::from_noun(result.root())? };
        match maybe_balance {
            Some(Some(balance)) => Ok(balance),
            _ => Err(NockAppError::OtherError(
                "wallet balance peek returned no balance payload".to_string(),
            )),
        }
    }

    /// Reads blockchain constants from wallet state so the planner uses live fee policy.
    async fn peek_planner_blockchain_constants(
        &mut self,
    ) -> Result<PlannerBlockchainConstantsNoun, NockAppError> {
        let mut slab = NounSlab::new();
        let constants_tag = make_tas(&mut slab, "blockchain-constants").as_noun();
        let path = T(&mut slab, &[constants_tag, SIG]);
        slab.set_root(path);

        let result = self.app.peek(slab).await?;
        let maybe_constants: Option<Option<PlannerBlockchainConstantsNoun>> =
            unsafe { <Option<Option<PlannerBlockchainConstantsNoun>>>::from_noun(result.root())? };
        let Some(constants) = maybe_constants.flatten() else {
            return Err(NockAppError::OtherError(
                "wallet blockchain-constants peek returned no payload".to_string(),
            ));
        };
        Ok(constants)
    }

    /// Normalizes signer key ordering and removes duplicates.
    fn planner_signer_keys(mut signer_keys: Vec<Hash>) -> Vec<Hash> {
        signer_keys.sort_by_key(Hash::to_array);
        signer_keys.dedup_by(|left, right| left.to_array() == right.to_array());
        signer_keys
    }

    /// Reads signer pubkey-hashes from wallet tracked state for lock matching.
    async fn peek_signing_keys(&mut self) -> Result<Vec<Hash>, NockAppError> {
        let signer_keys = self.peek_signing_keys_at_path("signing-keys").await?;
        Ok(Self::planner_signer_keys(signer_keys))
    }

    async fn peek_signing_pubkeys(&mut self) -> Result<Vec<SchnorrPubkey>, NockAppError> {
        self.peek_signing_pubkeys_at_path("signing-pubkeys").await
    }

    async fn peek_signing_keys_at_path(
        &mut self,
        path_tag: &str,
    ) -> Result<Vec<Hash>, NockAppError> {
        let mut slab = NounSlab::new();
        let tracked_tag = make_tas(&mut slab, path_tag).as_noun();
        let path = T(&mut slab, &[tracked_tag, SIG]);
        slab.set_root(path);

        let result = self.app.peek(slab).await?;
        let maybe_signing_keys: Option<Option<Vec<Hash>>> =
            unsafe { <Option<Option<Vec<Hash>>>>::from_noun(result.root())? };
        Ok(maybe_signing_keys.flatten().unwrap_or_default())
    }

    async fn peek_signing_pubkeys_at_path(
        &mut self,
        path_tag: &str,
    ) -> Result<Vec<SchnorrPubkey>, NockAppError> {
        let mut slab = NounSlab::new();
        let tracked_tag = make_tas(&mut slab, path_tag).as_noun();
        let path = T(&mut slab, &[tracked_tag, SIG]);
        slab.set_root(path);

        let result = self.app.peek(slab).await?;
        let maybe_signing_pubkeys: Option<Option<Vec<SchnorrPubkey>>> =
            unsafe { <Option<Option<Vec<SchnorrPubkey>>>>::from_noun(result.root())? };
        Ok(maybe_signing_pubkeys.flatten().unwrap_or_default())
    }

    #[cfg(test)]
    /// Builds deterministic signer candidate list used by tests.
    pub(crate) fn planner_signer_candidates(mut tracked_signers: Vec<Hash>) -> Vec<Option<Hash>> {
        tracked_signers.sort_by_key(|signer| signer.to_array());
        tracked_signers.dedup_by(|a, b| a.to_array() == b.to_array());
        let mut candidates = Vec::with_capacity(tracked_signers.len() + 1);
        candidates.push(None);
        candidates.extend(tracked_signers.into_iter().map(Some));
        candidates
    }

    /// Plans create-tx inputs/fee and dispatches final hoon create-tx poke.
    pub(crate) async fn create_tx_with_planner(
        &mut self,
        synced_snapshot: Option<NormalizedSnapshot>,
        names: Option<String>,
        fee: Option<u64>,
        recipients: Vec<RecipientSpec>,
        allow_low_fee: bool,
        refund_pkh: Option<String>,
        sign_keys: Vec<(u64, bool)>,
        include_data: bool,
        save_raw_tx: bool,
        note_selection: NoteSelectionStrategyCli,
    ) -> CommandNoun<NounSlab> {
        let planner_error = |reason: String| -> CommandNoun<NounSlab> {
            Err(CrownError::Unknown(format!("create-tx planner failed: {}", reason)).into())
        };

        let snapshot = if let Some(snapshot) = synced_snapshot {
            snapshot
        } else {
            let balance = match self.peek_balance_state().await {
                Ok(balance) => balance,
                Err(err) => {
                    return planner_error(format!(
                        "unable to read synced balance from wallet state: {err}"
                    ));
                }
            };
            match normalize_balance_pages(&[balance]) {
                Ok(snapshot) => snapshot,
                Err(err) => {
                    return planner_error(format!(
                        "candidate normalization failed for wallet balance snapshot: {err}"
                    ));
                }
            }
        };
        let v1_candidate_count = snapshot
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.version() == nockchain_types::tx_engine::common::Version::V1
            })
            .count();
        let candidate_preview = snapshot
            .candidates
            .iter()
            .take(5)
            .map(|candidate| {
                let identity = candidate.identity();
                format!(
                    "{}/{}",
                    identity.name.first.to_base58(),
                    identity.name.last.to_base58()
                )
            })
            .collect::<Vec<_>>();
        info!(
            "create-tx planner snapshot block={} height={:?} candidates_total={} candidates_v1={} preview={:?}",
            snapshot.metadata.block_id.to_base58(),
            snapshot.metadata.height,
            snapshot.candidates.len(),
            v1_candidate_count,
            candidate_preview
        );

        let manual_note_names = match names.as_deref() {
            Some(raw_names) => match Self::parse_note_names_as_hashes(raw_names) {
                Ok(note_names) => Some(note_names),
                Err(err) => {
                    return planner_error(format!("unable to parse manual note names: {err}"));
                }
            },
            None => None,
        };
        let selection_mode = match &manual_note_names {
            Some(note_names) => SelectionMode::Manual {
                note_names: note_names.clone(),
            },
            None => SelectionMode::Auto,
        };
        let parsed_refund_pkh = if let Some(refund) = refund_pkh.as_ref() {
            match Hash::from_base58(refund) {
                Ok(hash) => Some(hash),
                Err(err) => {
                    return planner_error(format!(
                        "invalid refund pubkey hash '{}': {}",
                        refund, err
                    ));
                }
            }
        } else {
            None
        };
        let candidate_version_policy = match &manual_note_names {
            Some(note_names) => {
                match Self::manual_candidate_version_policy(note_names, &snapshot.candidates) {
                    Ok(policy) => policy,
                    Err(err) => {
                        return planner_error(err);
                    }
                }
            }
            None => CandidateVersionPolicy::V1Only,
        };
        if candidate_version_policy == CandidateVersionPolicy::V0Only && parsed_refund_pkh.is_none()
        {
            return planner_error(
                "manual create-tx spending legacy v0 notes requires --refund-pkh".to_string(),
            );
        }
        if !sign_keys.is_empty() {
            info!(
                "create-tx planner spendability matching currently uses only the wallet master key"
            );
        }
        let signer_keys = match self.peek_signing_keys().await {
            Ok(keys) => keys,
            Err(err) => {
                warn!(
                    "create-tx planner could not read signing keys from wallet state: {}",
                    err
                );
                Vec::new()
            }
        };
        info!(
            "create-tx planner signer-keys entries={} signer-pkhs={:?}",
            signer_keys.len(),
            signer_keys.iter().map(Hash::to_base58).collect::<Vec<_>>()
        );
        let Some(master_signer_pkh) = signer_keys.first().cloned() else {
            return planner_error("wallet has no signer keys for create-tx planner".to_string());
        };
        let legacy_signer_pubkeys = if candidate_version_policy == CandidateVersionPolicy::V0Only {
            let signer_pubkeys = match self.peek_signing_pubkeys().await {
                Ok(keys) => keys,
                Err(err) => {
                    return planner_error(format!(
                        "unable to read signing pubkeys from wallet state: {err}"
                    ));
                }
            };
            let Some(master_signer_pubkey) = signer_pubkeys.first().cloned() else {
                return planner_error(
                    "wallet has no signer pubkeys for legacy create-tx planner".to_string(),
                );
            };
            vec![master_signer_pubkey]
        } else {
            Vec::new()
        };
        // Today lock matching is constrained to the master signer key only.
        // We can expand this matcher input to include additional signing keys later.
        let matcher_signer_keys = vec![master_signer_pkh.clone()];
        let recipient_outputs = match planner_recipient_outputs(&recipients, include_data) {
            Ok(outputs) => outputs,
            Err(err) => {
                return planner_error(format!(
                    "unable to derive planner recipient lock roots from recipients: {err}"
                ));
            }
        };
        let refund_output_template = match planner_refund_output_template(
            parsed_refund_pkh.as_ref(),
            &master_signer_pkh,
            include_data,
        ) {
            Ok(output) => output,
            Err(err) => {
                return planner_error(format!(
                    "unable to derive planner refund output template from signer/refund context: {err}"
                ));
            }
        };
        let planner_constants = match self.peek_planner_blockchain_constants().await {
            Ok(constants) => constants,
            Err(err) => {
                return planner_error(format!(
                    "unable to read blockchain constants from wallet state: {err}"
                ));
            }
        };
        let coinbase_relative_min = match planner_constants.coinbase_timelock_min() {
            Ok(min) => min,
            Err(err) => {
                return planner_error(format!(
                    "unable to resolve coinbase timelock min from blockchain constants: {err}"
                ));
            }
        };
        info!(
            "create-tx planner constants bythos_phase={} base_fee={} input_fee_divisor={} min_fee={} coinbase_relative_min={}",
            planner_constants.bythos_phase,
            planner_constants.base_fee,
            planner_constants.input_fee_divisor,
            planner_constants.data.min_fee,
            coinbase_relative_min
        );
        let order_direction = Self::planner_order_direction(note_selection);

        let request = PlanRequest {
            planning_mode: PlanningMode::Standard,
            selection_mode: selection_mode.clone(),
            order_direction,
            include_data,
            chain_context: ChainContext {
                height: snapshot.metadata.height.clone(),
                bythos_phase: nockchain_types::tx_engine::common::BlockHeight(
                    nockchain_math::belt::Belt(planner_constants.bythos_phase),
                ),
                base_fee: planner_constants.base_fee,
                input_fee_divisor: planner_constants.input_fee_divisor,
                min_fee: planner_constants.data.min_fee,
            },
            signer_pkh: Some(master_signer_pkh.clone()),
            candidate_version_policy,
            candidates: snapshot.candidates,
            recipient_outputs,
            refund_output: refund_output_template,
            coinbase_relative_min: Some(coinbase_relative_min),
            v0_migration_signer_pubkeys: legacy_signer_pubkeys,
        };

        let matcher = SigningKeyLockMatcher::from_signer_keys(&matcher_signer_keys);
        let plan = match plan_create_tx(&request, &matcher) {
            Ok(found_plan) => {
                info!(
                    "create-tx planner using master signer {} for lock spendability checks",
                    master_signer_pkh.to_base58()
                );
                found_plan
            }
            Err(err @ PlanError::CandidateVersionDisabled { .. }) => {
                return Err(CrownError::Unknown(format!(
                    "create-tx planner rejected the manual note set because it does not match the selected note version policy ({})",
                    err
                ))
                .into());
            }
            Err(err) => {
                return planner_error(format!("planner returned an error: {err}"));
            }
        };

        for trace in &plan.debug_trace {
            info!("create-tx planner trace: {}", trace);
        }

        let planned_names = plan
            .selected
            .iter()
            .map(|selected| selected.name.clone())
            .collect::<Vec<_>>();
        if let SelectionMode::Manual { note_names } = &selection_mode {
            if let Err(reason) = ensure_manual_planner_parity(note_names, &planned_names) {
                return planner_error(reason);
            }
        }
        let planned_names_arg = Self::format_note_names_for_create_tx(&planned_names);
        let planned_fee = plan.final_fee;
        let final_fee = if let Some(requested_fee) = fee {
            if requested_fee < planned_fee && !allow_low_fee {
                return Err(CrownError::Unknown(format!(
                    "requested --fee {} is below planner minimum {} (pass --allow-low-fee to override)",
                    requested_fee, planned_fee
                ))
                .into());
            }
            if requested_fee != planned_fee {
                info!(
                    "create-tx planner fee override requested_fee={} planned_fee={}",
                    requested_fee, planned_fee
                );
            }
            requested_fee
        } else {
            planned_fee
        };

        Self::create_tx(
            planned_names_arg, recipients, final_fee, allow_low_fee, refund_pkh, sign_keys,
            include_data, save_raw_tx, note_selection,
        )
    }

    /// Plans a full-sweep migration of spendable v0 notes into one v1 destination.
    pub(crate) async fn migrate_v0_notes_with_planner(
        &mut self,
        synced_snapshot: Option<NormalizedSnapshot>,
        destination: String,
    ) -> CommandNoun<NounSlab> {
        let planner_error = |reason: String| -> CommandNoun<NounSlab> {
            Err(CrownError::Unknown(format!("migrate-v0-notes planner failed: {}", reason)).into())
        };

        let destination_hash = match Hash::from_base58(&destination) {
            Ok(hash) => hash,
            Err(err) => {
                return planner_error(format!(
                    "invalid migration destination '{}' : {}",
                    destination, err
                ));
            }
        };
        let snapshot = if let Some(snapshot) = synced_snapshot {
            snapshot
        } else {
            let balance = match self.peek_balance_state().await {
                Ok(balance) => balance,
                Err(err) => {
                    return planner_error(format!(
                        "unable to read synced balance from wallet state: {err}"
                    ));
                }
            };
            match normalize_balance_pages(&[balance]) {
                Ok(snapshot) => snapshot,
                Err(err) => {
                    return planner_error(format!(
                        "candidate normalization failed for wallet balance snapshot: {err}"
                    ));
                }
            }
        };
        let v0_candidate_count = snapshot
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.version() == nockchain_types::tx_engine::common::Version::V0
            })
            .count();
        info!(
            "migrate-v0-notes snapshot block={} height={:?} candidates_total={} candidates_v0={}",
            snapshot.metadata.block_id.to_base58(),
            snapshot.metadata.height,
            snapshot.candidates.len(),
            v0_candidate_count,
        );

        let signer_pubkeys = match self.peek_signing_pubkeys().await {
            Ok(keys) => keys,
            Err(err) => {
                return planner_error(format!(
                    "unable to read signing pubkeys from wallet state: {err}"
                ));
            }
        };
        let Some(master_signer_pubkey) = signer_pubkeys.first().cloned() else {
            return planner_error(
                "wallet has no signer pubkeys for migrate-v0-notes planner".to_string(),
            );
        };
        let destination_output = match planner_recipient_outputs(
            &[RecipientSpec::P2pkh {
                address: destination_hash.clone(),
                amount: 0,
            }],
            true,
        ) {
            Ok(mut outputs) => outputs
                .pop()
                .expect("single migration recipient should yield one planner output"),
            Err(err) => {
                return planner_error(format!(
                    "unable to derive migration destination output from recipient: {err}"
                ));
            }
        };
        let planner_constants = match self.peek_planner_blockchain_constants().await {
            Ok(constants) => constants,
            Err(err) => {
                return planner_error(format!(
                    "unable to read blockchain constants from wallet state: {err}"
                ));
            }
        };
        let coinbase_relative_min = match planner_constants.coinbase_timelock_min() {
            Ok(min) => min,
            Err(err) => {
                return planner_error(format!(
                    "unable to resolve coinbase timelock min from blockchain constants: {err}"
                ));
            }
        };
        let request = PlanRequest {
            planning_mode: PlanningMode::V0MigrationSweep { destination_output },
            selection_mode: SelectionMode::Auto,
            order_direction: SelectionOrder::Ascending,
            include_data: true,
            chain_context: ChainContext {
                height: snapshot.metadata.height.clone(),
                bythos_phase: nockchain_types::tx_engine::common::BlockHeight(
                    nockchain_math::belt::Belt(planner_constants.bythos_phase),
                ),
                base_fee: planner_constants.base_fee,
                input_fee_divisor: planner_constants.input_fee_divisor,
                min_fee: planner_constants.data.min_fee,
            },
            signer_pkh: None,
            candidate_version_policy: CandidateVersionPolicy::V0Only,
            candidates: snapshot.candidates,
            recipient_outputs: Vec::new(),
            refund_output: planner_refund_output_template(
                Some(&destination_hash),
                &destination_hash,
                true,
            )
            .expect("p2pkh migration refund template should build"),
            coinbase_relative_min: Some(coinbase_relative_min),
            v0_migration_signer_pubkeys: vec![master_signer_pubkey],
        };

        let plan = match plan_create_tx(&request, &SigningKeyLockMatcher::default()) {
            Ok(found_plan) => found_plan,
            Err(err) => {
                return planner_error(format!("planner returned an error: {err}"));
            }
        };

        for trace in &plan.debug_trace {
            info!("migrate-v0-notes planner trace: {}", trace);
        }

        let planned_names = plan
            .selected
            .iter()
            .map(|selected| selected.name.clone())
            .collect::<Vec<_>>();
        let Some(sweep_output) = plan.outputs.first() else {
            return planner_error("migration planner returned no destination output".to_string());
        };

        Self::create_tx(
            Self::format_note_names_for_create_tx(&planned_names),
            vec![RecipientSpec::P2pkh {
                address: destination_hash.clone(),
                amount: sweep_output.amount,
            }],
            plan.final_fee,
            false,
            Some(destination_hash.to_base58()),
            Vec::new(),
            true,
            false,
            NoteSelectionStrategyCli::Ascending,
        )
    }

    /// Creates a transaction. Use `--refund-pkh` when spending legacy v0 notes so the kernel
    /// knows where to return change. When spending v1 notes the refund automatically
    /// defaults back to the note owner, so `--refund-pkh` can be omitted.
    fn create_tx(
        names: String,
        recipients: Vec<RecipientSpec>,
        fee: u64,
        allow_low_fee: bool,
        refund_pkh: Option<String>,
        sign_keys: Vec<(u64, bool)>,
        include_data: bool,
        save_raw_tx: bool,
        note_selection: NoteSelectionStrategyCli,
    ) -> CommandNoun<NounSlab> {
        let mut slab = NounSlab::new();

        let names_vec = Self::parse_note_names(&names)?;
        let names_noun = names_vec
            .into_iter()
            .rev()
            .fold(D(0), |acc, (first, last)| {
                let first_noun = make_tas(&mut slab, &first).as_noun();
                let last_noun = make_tas(&mut slab, &last).as_noun();
                let name_pair = T(&mut slab, &[first_noun, last_noun]);
                Cell::new(&mut slab, name_pair, acc).as_noun()
            });

        let fee_noun = D(fee);
        let order_noun = recipients.to_noun(&mut slab);
        let sign_key_noun = Wallet::encode_sign_keys(&mut slab, sign_keys);

        let refund_noun = if let Some(refund) = refund_pkh {
            let refund_hash = Hash::from_base58(&refund).map_err(|err| {
                NockAppError::from(CrownError::Unknown(format!(
                    "Invalid refund pubkey hash '{}': {}",
                    refund, err
                )))
            })?;
            let refund_atom = refund_hash.to_noun(&mut slab);
            T(&mut slab, &[SIG, refund_atom])
        } else {
            SIG
        };
        let include_data_noun = include_data.to_noun(&mut slab);
        let allow_low_fee_noun = allow_low_fee.to_noun(&mut slab);
        let save_raw_tx_noun = save_raw_tx.to_noun(&mut slab);
        let note_selection_noun = make_tas(&mut slab, note_selection.tas_label()).as_noun();

        Self::wallet(
            "create-tx",
            &[
                names_noun, order_noun, fee_noun, allow_low_fee_noun, sign_key_noun, refund_noun,
                include_data_noun, save_raw_tx_noun, note_selection_noun,
            ],
            Operation::Poke,
            &mut slab,
        )
    }

    #[cfg(test)]
    pub(crate) fn create_tx_command_for_tests(
        names: String,
        recipients: Vec<RecipientSpec>,
        fee: u64,
        allow_low_fee: bool,
        refund_pkh: Option<String>,
        sign_keys: Vec<(u64, bool)>,
        include_data: bool,
        save_raw_tx: bool,
        note_selection: NoteSelectionStrategyCli,
    ) -> CommandNoun<NounSlab> {
        Self::create_tx(
            names, recipients, fee, allow_low_fee, refund_pkh, sign_keys, include_data,
            save_raw_tx, note_selection,
        )
    }

    /// Encodes optional sign-key tuples for wallet kernel create-tx commands.
    fn encode_sign_keys(slab: &mut NounSlab, keys: Vec<(u64, bool)>) -> Noun {
        if keys.is_empty() {
            SIG
        } else {
            Some(keys).to_noun(slab)
        }
    }

    /// Builds one `update-balance-grpc` poke from a fully assembled balance snapshot.
    fn update_balance_grpc_poke(balance_update: v1::BalanceUpdate) -> NounSlab {
        let mut slab = NounSlab::new();
        let wrapped_balance = Some(Some(balance_update));
        let balance_noun = wrapped_balance.to_noun(&mut slab);
        let head = make_tas(&mut slab, "update-balance-grpc").as_noun();
        let full = T(&mut slab, &[head, balance_noun]);
        slab.set_root(full);
        slab
    }

    #[cfg(test)]
    pub(crate) fn update_balance_grpc_poke_for_tests(
        balance_update: v1::BalanceUpdate,
    ) -> NounSlab {
        Self::update_balance_grpc_poke(balance_update)
    }

    /// Merges fetched balance pages into one consistent deduplicated snapshot.
    pub(crate) fn union_balance_pages(
        pages: Vec<v1::BalanceUpdate>,
    ) -> Result<Option<(v1::BalanceUpdate, NormalizedSnapshot)>, NormalizeSnapshotError> {
        if pages.is_empty() {
            return Ok(None);
        }

        let normalized = normalize_balance_pages(&pages)?;

        let mut deduped_notes = BTreeMap::<([u64; 5], [u64; 5]), (Name, v1::Note)>::new();
        for page in pages {
            for (name, note) in page.notes.0 {
                let key = (name.first.to_array(), name.last.to_array());
                deduped_notes.entry(key).or_insert((name, note));
            }
        }

        let merged = v1::BalanceUpdate {
            height: normalized.metadata.height.clone(),
            block_id: normalized.metadata.block_id.clone(),
            notes: v1::Balance(deduped_notes.into_values().collect()),
        };
        Ok(Some((merged, normalized)))
    }

    #[cfg(test)]
    /// Removes v1 notes that do not match tracked first-name filters.
    ///
    /// Some balance endpoints can return broader result sets than requested.
    /// This keeps wallet state aligned with tracked keys/watch lists by
    /// admitting only v1 notes whose first-name matches a tracked query.
    fn filter_untracked_v1_notes_from_balance_update(
        mut balance_update: v1::BalanceUpdate,
        tracked_first_names: &std::collections::BTreeSet<[u64; 5]>,
    ) -> v1::BalanceUpdate {
        if tracked_first_names.is_empty() {
            return balance_update;
        }

        let before = balance_update.notes.0.len();
        balance_update.notes.0.retain(|(name, note)| match note {
            v1::Note::V1(_) => tracked_first_names.contains(&name.first.to_array()),
            v1::Note::V0(_) => true,
        });
        let removed = before.saturating_sub(balance_update.notes.0.len());
        if removed > 0 {
            info!(
                "wallet balance sync dropped {} untracked v1 notes from one page",
                removed
            );
        }
        balance_update
    }

    /// Builds one `update-balance-grpc` poke from a private-api peek payload.
    fn update_balance_grpc_poke_from_payload(
        payload: Option<Option<v1::BalanceUpdate>>,
    ) -> NounSlab {
        let mut slab = NounSlab::new();
        let payload_noun = payload.to_noun(&mut slab);
        let head = make_tas(&mut slab, "update-balance-grpc").as_noun();
        let full = T(&mut slab, &[head, payload_noun]);
        slab.set_root(full);
        slab
    }

    #[cfg(test)]
    /// Test helper for filtering one balance update against tracked first names.
    pub(crate) fn filter_untracked_v1_notes_for_tests(
        balance_update: v1::BalanceUpdate,
        tracked_first_names: Vec<Hash>,
    ) -> v1::BalanceUpdate {
        let tracked = tracked_first_names
            .into_iter()
            .map(|hash| hash.to_array())
            .collect::<std::collections::BTreeSet<_>>();
        Self::filter_untracked_v1_notes_from_balance_update(balance_update, &tracked)
    }

    /// Collects one page set from the public API balance endpoints.
    async fn fetch_balance_pages_grpc_public(
        client: &mut public_nockchain::PublicNockchainGrpcClient,
        pubkeys: &[String],
        first_names: &[String],
    ) -> Result<Vec<v1::BalanceUpdate>, NockAppError> {
        let mut pages = Vec::<v1::BalanceUpdate>::new();

        for first_name in first_names {
            let response = client
                .wallet_get_balance(&BalanceRequest::FirstName(first_name.clone()))
                .await
                .map_err(|e| {
                    NockAppError::OtherError(format!(
                        "Failed to request current balance for first name {}: {}",
                        first_name, e
                    ))
                })?;
            let balance_update = v1::BalanceUpdate::try_from(response).map_err(|e| {
                NockAppError::OtherError(format!(
                    "Failed to parse balance update for first name {}: {}",
                    first_name, e
                ))
            })?;
            pages.push(balance_update);
        }

        for key in pubkeys {
            let response = client
                .wallet_get_balance(&BalanceRequest::Address(key.clone()))
                .await
                .map_err(|e| {
                    NockAppError::OtherError(format!(
                        "Failed to request current balance for pubkey {}: {}",
                        key, e
                    ))
                })?;
            let balance_update = v1::BalanceUpdate::try_from(response).map_err(|e| {
                NockAppError::OtherError(format!(
                    "Failed to parse balance update for pubkey {}: {}",
                    key, e
                ))
            })?;
            pages.push(balance_update);
        }

        Ok(pages)
    }

    /// Fetches balances via public gRPC and emits one merged wallet update snapshot.
    pub(crate) async fn update_balance_grpc_public(
        client: &mut public_nockchain::PublicNockchainGrpcClient,
        mut pubkeys: Vec<String>,
        mut first_names: Vec<String>,
    ) -> Result<connection::BalanceSyncResult, NockAppError> {
        first_names.sort();
        first_names.dedup();
        pubkeys.sort();
        pubkeys.dedup();

        const SNAPSHOT_DRIFT_MAX_RETRIES: usize = 2;
        let mut attempt = 0usize;
        let (merged_balance, normalized_snapshot) = loop {
            attempt = attempt.saturating_add(1);
            let pages =
                Self::fetch_balance_pages_grpc_public(client, &pubkeys, &first_names).await?;

            match Self::union_balance_pages(pages) {
                Ok(Some((merged_balance, normalized_snapshot))) => {
                    break (merged_balance, normalized_snapshot);
                }
                Ok(None) => {
                    return Ok(connection::BalanceSyncResult {
                        pokes: Vec::new(),
                        normalized_snapshot: None,
                    });
                }
                Err(
                    NormalizeSnapshotError::Snapshot(SnapshotConsistencyError::HeightDrift)
                    | NormalizeSnapshotError::Snapshot(SnapshotConsistencyError::BlockIdDrift),
                ) if attempt <= SNAPSHOT_DRIFT_MAX_RETRIES => {
                    continue;
                }
                Err(err) => {
                    return Err(NockAppError::OtherError(format!(
                        "Failed to normalize fetched wallet balance pages into one snapshot: {}",
                        err
                    )));
                }
            }
        };

        Ok(connection::BalanceSyncResult {
            pokes: vec![Self::update_balance_grpc_poke(merged_balance)],
            normalized_snapshot: Some(normalized_snapshot),
        })
    }

    /// Fetches balances via private gRPC peek paths and wraps updates as wallet pokes.
    pub(crate) async fn update_balance_grpc_private(
        client: &mut private_nockapp::PrivateNockAppGrpcClient,
        mut pubkeys: Vec<String>,
        mut first_names: Vec<String>,
    ) -> Result<connection::BalanceSyncResult, NockAppError> {
        first_names.sort();
        first_names.dedup();
        pubkeys.sort();
        pubkeys.dedup();

        let mut request_index: i32 = 0;
        let mut results = Vec::new();

        for first_name in first_names {
            let mut slab: NounSlab<NockJammer> = NounSlab::new();

            let mut path_slab = NounSlab::<NockJammer>::new();
            let path_noun = vec!["balance-by-first-name".to_string(), first_name.clone()]
                .to_noun(&mut path_slab);
            path_slab.set_root(path_noun);
            let path_bytes = path_slab.jam().to_vec();

            let response = client.peek(request_index, path_bytes).await.map_err(|e| {
                NockAppError::OtherError(format!(
                    "Failed to peek balance for first name {first_name}: {e}"
                ))
            })?;
            request_index = request_index.wrapping_add(1);

            let balance = slab.cue_into(response.as_bytes()?)?;
            let payload: Option<Option<v1::BalanceUpdate>> =
                <Option<Option<v1::BalanceUpdate>>>::from_noun(&balance)?;
            results.push(Self::update_balance_grpc_poke_from_payload(payload));
        }

        for key in pubkeys {
            let mut slab: NounSlab<NockJammer> = NounSlab::new();
            let mut path_slab = NounSlab::<NockJammer>::new();
            let path_noun =
                vec!["balance-by-pubkey".to_string(), key.clone()].to_noun(&mut path_slab);
            path_slab.set_root(path_noun);
            let path_bytes = path_slab.jam().to_vec();

            let response = client.peek(request_index, path_bytes).await.map_err(|e| {
                NockAppError::OtherError(format!("Failed to peek balance for pubkey {key}: {e}"))
            })?;
            request_index = request_index.wrapping_add(1);

            let balance = slab.cue_into(response.as_bytes()?)?;
            let payload: Option<Option<v1::BalanceUpdate>> =
                <Option<Option<v1::BalanceUpdate>>>::from_noun(&balance)?;
            results.push(Self::update_balance_grpc_poke_from_payload(payload));
        }

        Ok(connection::BalanceSyncResult {
            pokes: results,
            normalized_snapshot: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use nockchain_math::belt::Belt;
    use nockchain_math::crypto::cheetah::A_GEN;
    use nockchain_types::tx_engine::common::{BlockHeight, Nicks, SchnorrPubkey};
    use nockchain_types::tx_engine::v0::Lock as V0Lock;
    use wallet_tx_builder::note_data::DecodedNoteData;
    use wallet_tx_builder::types::{
        CandidateIdentity, CandidateV0Note, CandidateV1Note, CandidateVersionPolicy,
    };

    use super::*;

    fn hash(v: u64) -> Hash {
        Hash::from_limbs(&[v, 0, 0, 0, 0])
    }

    fn name(first: u64, last: u64) -> Name {
        Name::new(hash(first), hash(last))
    }

    fn candidate_v0(first: u64, last: u64) -> CandidateNote {
        CandidateNote::V0(CandidateV0Note {
            identity: CandidateIdentity {
                name: name(first, last),
                origin_page: BlockHeight(Belt(1)),
            },
            assets: Nicks(1),
            lock: V0Lock {
                keys_required: 1,
                pubkeys: vec![SchnorrPubkey(A_GEN)],
            },
            timelock: None,
        })
    }

    fn candidate_v1(first: u64, last: u64) -> CandidateNote {
        CandidateNote::V1(CandidateV1Note {
            identity: CandidateIdentity {
                name: name(first, last),
                origin_page: BlockHeight(Belt(1)),
            },
            assets: Nicks(1),
            raw_note_data: Vec::new(),
            decoded_note_data: DecodedNoteData(Vec::new()),
        })
    }

    #[test]
    fn manual_candidate_version_policy_returns_v0_only_for_all_v0_manual_sets() {
        let note_names = vec![name(1, 10), name(2, 20)];
        let candidates = vec![candidate_v0(1, 10), candidate_v0(2, 20), candidate_v1(3, 30)];

        let policy =
            Wallet::manual_candidate_version_policy(&note_names, &candidates).expect("policy");

        assert_eq!(policy, CandidateVersionPolicy::V0Only);
    }

    #[test]
    fn manual_candidate_version_policy_returns_v1_only_for_all_v1_manual_sets() {
        let note_names = vec![name(3, 30)];
        let candidates = vec![candidate_v0(1, 10), candidate_v1(3, 30)];

        let policy =
            Wallet::manual_candidate_version_policy(&note_names, &candidates).expect("policy");

        assert_eq!(policy, CandidateVersionPolicy::V1Only);
    }

    #[test]
    fn manual_candidate_version_policy_rejects_mixed_manual_sets() {
        let note_names = vec![name(1, 10), name(3, 30)];
        let candidates = vec![candidate_v0(1, 10), candidate_v1(3, 30)];

        let err = Wallet::manual_candidate_version_policy(&note_names, &candidates)
            .expect_err("mixed version note set should error");

        assert_eq!(
            err,
            "manual create-tx cannot mix v0 and v1 notes; select notes from only one version"
        );
    }

    #[test]
    fn manual_candidate_version_policy_rejects_missing_manual_notes() {
        let missing = name(9, 90);
        let note_names = vec![missing.clone()];
        let candidates = vec![candidate_v0(1, 10), candidate_v1(3, 30)];

        let err = Wallet::manual_candidate_version_policy(&note_names, &candidates)
            .expect_err("missing note should error");

        assert_eq!(
            err,
            format!(
                "manual mode references unknown note {}/{}",
                missing.first.to_base58(),
                missing.last.to_base58()
            )
        );
    }
}
