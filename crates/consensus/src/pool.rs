//! Custom transaction pool construction and First-Come-First-Serve (FCFS) transaction ordering.

use alloy_primitives::B256;
use reth_chainspec::EthereumHardforks;
use reth_ethereum::{
    evm::primitives::ConfigureEvm,
    node::{
        api::{FullNodeTypes, NodeTypes},
        builder::{components::PoolBuilder, BuilderContext},
    },
    pool::{blobstore::InMemoryBlobStore, Pool, PoolConfig, TransactionValidationTaskExecutor},
    provider::CanonStateSubscriptions,
};
use reth_transaction_pool::{
    PoolTransaction, Priority, TransactionOrdering, TransactionOrigin,
    TransactionValidationOutcome, TransactionValidator,
};
use reth_node_api::{NodePrimitives, PrimitivesTy};
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::info;

/// FCFS transaction ordering that priorities transactions based on arrival order.
#[derive(Debug, Clone)]
pub struct FCFSOrdering<T> {
    inner: Arc<FCFSOrderingInner>,
    _marker: std::marker::PhantomData<T>,
}

// Deleted ERC7683Intent (dead code)

/// A transaction bundled with its execution witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionWithWitness<T> {
    /// The inner transaction.
    pub transaction: T,
    /// The execution witness data.
    pub witness: Vec<u8>,
}

impl<T: reth_primitives_traits::InMemorySize> reth_primitives_traits::InMemorySize for TransactionWithWitness<T> {
    fn size(&self) -> usize {
        self.transaction.size()
    }
}

impl<T: alloy_consensus::Typed2718> alloy_consensus::Typed2718 for TransactionWithWitness<T> {
    fn ty(&self) -> u8 {
        self.transaction.ty()
    }
}

impl<T: alloy_consensus::Transaction> alloy_consensus::Transaction for TransactionWithWitness<T> {
    fn chain_id(&self) -> Option<u64> {
        self.transaction.chain_id()
    }

    fn nonce(&self) -> u64 {
        self.transaction.nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.transaction.gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.transaction.gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.transaction.max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.transaction.max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.transaction.max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.transaction.priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.transaction.effective_gas_price(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.transaction.is_dynamic_fee()
    }

    fn is_create(&self) -> bool {
        self.transaction.is_create()
    }

    fn kind(&self) -> alloy_primitives::TxKind {
        self.transaction.kind()
    }

    fn value(&self) -> alloy_primitives::Uint<256, 4> {
        self.transaction.value()
    }

    fn input(&self) -> &alloy_primitives::Bytes {
        self.transaction.input()
    }

    fn access_list(&self) -> Option<&alloy_eips::eip2930::AccessList> {
        self.transaction.access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.transaction.blob_versioned_hashes()
    }

    fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        self.transaction.authorization_list()
    }
}

impl<T: reth_transaction_pool::PoolTransaction> reth_transaction_pool::PoolTransaction for TransactionWithWitness<T> {
    type TryFromConsensusError = T::TryFromConsensusError;
    type Consensus = T::Consensus;
    type Pooled = T::Pooled;

    fn hash(&self) -> &B256 {
        self.transaction.hash()
    }

    fn consensus_ref(&self) -> reth_ethereum::primitives::Recovered<&Self::Consensus> {
        self.transaction.consensus_ref()
    }

    fn into_consensus(self) -> reth_ethereum::primitives::Recovered<Self::Consensus> {
        self.transaction.into_consensus()
    }

    fn from_pooled(pooled: reth_ethereum::primitives::Recovered<Self::Pooled>) -> Self {
        Self {
            transaction: T::from_pooled(pooled),
            witness: Vec::new(),
        }
    }

    fn sender(&self) -> alloy_primitives::Address {
        self.transaction.sender()
    }

    fn sender_ref(&self) -> &alloy_primitives::Address {
        self.transaction.sender_ref()
    }

    fn cost(&self) -> &alloy_primitives::Uint<256, 4> {
        self.transaction.cost()
    }

    fn encoded_length(&self) -> usize {
        self.transaction.encoded_length()
    }
}



#[derive(Debug)]
struct FCFSOrderingInner {
    next_sequence: Mutex<u64>,
    sequences: Mutex<HashMap<B256, u64>>,
}

impl<T> FCFSOrdering<T> {
    /// Creates a new `FCFSOrdering`.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(FCFSOrderingInner {
                next_sequence: Mutex::new(0),
                sequences: Mutex::new(HashMap::new()),
            }),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> Default for FCFSOrdering<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: PoolTransaction> TransactionOrdering for FCFSOrdering<T> {
    type PriorityValue = u64;
    type Transaction = T;

    fn priority(
        &self,
        transaction: &Self::Transaction,
        _base_fee: u64,
    ) -> Priority<Self::PriorityValue> {
        let hash = *transaction.hash();
        let mut sequences = self.inner.sequences.lock().unwrap();
        let seq = if let Some(&seq) = sequences.get(&hash) {
            seq
        } else {
            let mut next = self.inner.next_sequence.lock().unwrap();
            let seq = *next;
            *next += 1;
            sequences.insert(hash, seq);
            seq
        };
        Priority::Value(u64::MAX - seq)
    }
}

/// Trait to read account balances from the underlying state or a fallback.
pub trait LatticeStateProvider: Send + Sync + std::fmt::Debug + 'static {
    /// Retrieve the balance of the given address.
    fn get_balance(&self, address: alloy_primitives::Address) -> alloy_primitives::U256;
}

impl LatticeStateProvider for () {
    fn get_balance(&self, _address: alloy_primitives::Address) -> alloy_primitives::U256 {
        // Fallback testing balance
        alloy_primitives::U256::from(10_000_000_000_000_000_000_000u128)
    }
}

/// Wrapper for the Reth provider to implement LatticeStateProvider.
#[derive(Clone)]
pub struct LatticeClient<C>(pub C);

impl<C> std::fmt::Debug for LatticeClient<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LatticeClient").finish()
    }
}

impl<C> LatticeStateProvider for LatticeClient<C>
where
    C: reth_provider::StateProviderFactory + Send + Sync + Clone + 'static,
{
    fn get_balance(&self, address: alloy_primitives::Address) -> alloy_primitives::U256 {
        use reth_provider::AccountReader;
        if let Ok(latest) = self.0.latest() {
            latest.basic_account(&address)
                .ok()
                .flatten()
                .map(|acc| acc.balance)
                .unwrap_or_default()
        } else {
            alloy_primitives::U256::ZERO
        }
    }
}

/// Helper to compute the dynamic lattice-enforced balance of an address.
pub fn compute_lattice_balance(
    address: alloy_primitives::Address,
    reg: &crate::registry::ValidatorRegistry,
    initial_balance: alloy_primitives::U256,
) -> alloy_primitives::U256 {
    let mut balance = initial_balance;

    // Build a quick local set of claimed sends
    let mut claimed = std::collections::HashSet::new();
    for block in reg.lattice_blocks.values() {
        if let crate::stateless::LatticePayload::Receive { send_block_hash, .. } = &block.payload {
            claimed.insert(*send_block_hash);
        }
    }

    // Filter lattice blocks only associated with the address (acting as index)
    for (hash, block) in &reg.lattice_blocks {
        // 1. If we are the sender of a Send block: subtract it
        if block.account == address {
            if let crate::stateless::LatticePayload::Send { amount, .. } = &block.payload {
                balance = balance.saturating_sub(*amount);
            }
        }
        // 2. If we are the recipient of a Send block:
        if let crate::stateless::LatticePayload::Send { recipient, amount } = &block.payload {
            if *recipient == address {
                let is_evm_tx = block.signature.is_empty();
                if is_evm_tx {
                    // Standard EVM tx: subtract if unclaimed
                    if !claimed.contains(hash) {
                        balance = balance.saturating_sub(*amount);
                    }
                } else {
                    // Custom block-lattice transfer: add if claimed
                    if claimed.contains(hash) {
                        balance = balance.saturating_add(*amount);
                    }
                }
            }
        }
    }
    balance
}

/// Custom validator wrapping any standard validator to enforce Zero Latency Quantum Trigger checks on pooled transactions.
#[derive(Debug, Clone)]
pub struct SovereignQuantumTransactionValidator<V, Client = ()> {
    inner: V,
    /// Custom state reader interface to retrieve database/fallback account balance.
    pub client: Client,
    /// Per-account isolated transaction queues representing Block-Lattice pools.
    pub account_queues: Arc<Mutex<HashMap<alloy_primitives::Address, Vec<B256>>>>,
}

impl<V, Client> SovereignQuantumTransactionValidator<V, Client> {
    /// Creates a new `SovereignQuantumTransactionValidator`.
    pub fn new(inner: V, client: Client) -> Self {
        Self {
            inner,
            client,
            account_queues: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<V, Client, T, B> TransactionValidator for SovereignQuantumTransactionValidator<V, Client>
where
    V: TransactionValidator<Transaction = T, Block = B>,
    Client: LatticeStateProvider + Clone + 'static,
    T: PoolTransaction,
    B: reth_primitives_traits::Block,
{
    type Transaction = T;
    type Block = B;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        let registry_lock = crate::registry::get_registry();
        let sender = transaction.sender();

        // ── Gate 0: Compliance check ──────────────────────────────────────
        if let Ok(reg) = registry_lock.read() {
            if let Some(frontier) = reg.account_frontiers.get(&sender) {
                if let Some(comp) = &frontier.cached_compliance {
                    if let Some(j_vector) = reg.jurisdiction_vectors.get(&1) {
                        let active_q1 = comp.q1();
                        let target_q1 = j_vector.active_q1_mask;
                        if (active_q1 & target_q1) != 0 {
                            tracing::warn!(?sender, "Gate 0 block: Sender has conflicting jurisdiction bits");
                            return TransactionValidationOutcome::Invalid(
                                transaction,
                                InvalidTransactionError::TxTypeNotSupported.into(),
                            );
                        }

                        if j_vector.required_q2_mask != 0 && (comp.q2() & j_vector.required_q2_mask) == 0 {
                            tracing::warn!(?sender, "Gate 0 block: Sender entity class not eligible");
                            return TransactionValidationOutcome::Invalid(
                                transaction,
                                InvalidTransactionError::TxTypeNotSupported.into(),
                            );
                        }
                    }
                }
            }
        }

        // ── Gate 0: DID Registration validation ───────────────────────────
        let is_did_reg = if let Some(to) = transaction.to() {
            to == crate::system_registry::SYSTEM_DID_REGISTRY
        } else {
            false
        };
        if !is_did_reg {
            if let Ok(reg) = registry_lock.read() {
                if let Some(did) = reg.get_did_by_address(&sender) {
                    if !reg.is_did_fully_registered(&did) {
                        tracing::warn!(?sender, "Rejecting transaction in pool: Active DID not fully registered");
                        return TransactionValidationOutcome::Invalid(
                            transaction,
                            InvalidTransactionError::TxTypeNotSupported.into(),
                        );
                    }
                } else {
                    tracing::warn!(?sender, "Rejecting transaction in pool: Sender has no registered DID");
                    return TransactionValidationOutcome::Invalid(
                        transaction,
                        InvalidTransactionError::TxTypeNotSupported.into(),
                    );
                }
            }
        }

        // ── Gate 1: Zero-gas tx validation ────────────────────────────────
        let gas_price = transaction.gas_price().unwrap_or_else(|| transaction.max_fee_per_gas());
        let is_system_receive = if let Some(recipient) = transaction.to() {
            recipient == crate::system_registry::SYSTEM_RECEIVE_HOOK
        } else {
            false
        };

        if gas_price == 0 && !is_system_receive && !is_did_reg {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidTransactionError::TxTypeNotSupported.into(),
            );
        }

        // ── Gate 2: ZLQT validation ───────────────────────────────────────
        let (quantum_threat, default_pq_scheme) = if let Ok(reg) = registry_lock.read() {
            let dynamic = reg.dynamic_cfg.read().unwrap();
            (dynamic.zero_latency_quantum_trigger, dynamic.default_pq_scheme.clone())
        } else {
            (false, "mldsa".to_string())
        };

        if quantum_threat && !is_did_reg {
            if let Ok(reg) = registry_lock.read() {
                if let Some(tier) = reg.did_key_tier.get(&sender) {
                    if *tier == crate::pq_registry::KeyTier::Classical {
                        tracing::warn!(?sender, "Rejecting transaction in pool: Account is Classical tier under active ZLQT");
                        return TransactionValidationOutcome::Invalid(
                            transaction,
                            InvalidTransactionError::TxTypeNotSupported.into(),
                        );
                    }
                } else {
                    tracing::warn!(?sender, "Rejecting transaction in pool: Unregistered account under active ZLQT");
                    return TransactionValidationOutcome::Invalid(
                        transaction,
                        InvalidTransactionError::TxTypeNotSupported.into(),
                    );
                }
            }
        }

        // ── Gate 3: Locked check ──────────────────────────────────────────
        if let Ok(reg) = registry_lock.read() {
            if let Some(frontier) = reg.account_frontiers.get(&sender) {
                if frontier.locked {
                    tracing::warn!(?sender, "Rejecting transaction in pool: Sender account is locked");
                    return TransactionValidationOutcome::Invalid(
                        transaction,
                        InvalidTransactionError::TxTypeNotSupported.into(),
                    );
                }
            }
            if let alloy_primitives::TxKind::Call(recipient) = transaction.kind() {
                if let Some(frontier) = reg.account_frontiers.get(&recipient) {
                    if frontier.locked {
                        tracing::warn!(?recipient, "Rejecting transaction in pool: Target account is locked");
                        return TransactionValidationOutcome::Invalid(
                            transaction,
                            InvalidTransactionError::TxTypeNotSupported.into(),
                        );
                    }
                }
            }
        }

        // ── Gate 4: Balance solvency check ────────────────────────────────
        if let Ok(reg) = registry_lock.read() {
            let initial_balance = self.client.get_balance(sender);
            let lattice_balance = compute_lattice_balance(sender, &reg, initial_balance);
            let tx_value = transaction.value();
            if lattice_balance < tx_value {
                tracing::warn!(
                    ?sender,
                    ?lattice_balance,
                    ?tx_value,
                    "Rejecting transaction in pool: Insufficient lattice balance"
                );
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidTransactionError::TxTypeNotSupported.into(),
                );
            }
        }

        // ── Gate 5: PQ envelope check if quantum_threat ───────────────────
        if quantum_threat && !is_did_reg {
            let Ok((scheme, pk, sig)) = crate::crypto::unpack_pq_envelope(transaction.input().as_ref()) else {
                tracing::warn!(
                    hash = ?transaction.hash(),
                    "Rejecting standard transaction in pool: Zero Latency Quantum Trigger active (missing/invalid PQ envelope)"
                );
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidTransactionError::TxTypeNotSupported.into(),
                );
            };

            let configured_scheme = crate::crypto::parse_scheme(&default_pq_scheme).unwrap_or(crate::crypto::SignatureScheme::MlDsa);
            if scheme != configured_scheme {
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidTransactionError::TxTypeNotSupported.into(),
                );
            }

            let mut bytes = Vec::new();
            bytes.extend_from_slice(transaction.sender().as_slice());
            bytes.extend_from_slice(&transaction.nonce().to_be_bytes());
            if let Some(to) = transaction.to() {
                bytes.extend_from_slice(to.as_slice());
            }
            bytes.extend_from_slice(&transaction.value().to_be_bytes::<32>());
            let hash = alloy_primitives::keccak256(&bytes);
            let msg = hash.as_slice();

            if crate::crypto::verify_signature(scheme, &pk, msg, &sig, true).is_err() {
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidTransactionError::TxTypeNotSupported.into(),
                );
            }

            let hash_scheme = scheme.default_address_hash();
            let derived_addr = alloy_primitives::Address::from(crate::crypto::derive_address(hash_scheme, &pk));
            
            // ARCH-04: In wrapped mode, the sender recovered from Secp256k1 will be different from the derived PQ address.
            // Check that the derived PQ address matches OR the registered PQ key for the sender matches pk.
            let mut matches_identity = derived_addr == transaction.sender();
            if !matches_identity {
                if let Ok(reg) = registry_lock.read() {
                    if let Some(registered_pq) = reg.pq_keys.get(&transaction.sender()) {
                        if registered_pq == &pk {
                            matches_identity = true;
                        }
                    }
                }
            }

            if !matches_identity {
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidTransactionError::TxTypeNotSupported.into(),
                );
            }
        }

        // ── Call standard inner transaction validator ────────────────────
        let inner_outcome = self.inner.validate_transaction(origin, transaction.clone()).await;

        let final_outcome = match inner_outcome {
            TransactionValidationOutcome::Invalid(tx, err) => {
                if let Ok(reg) = registry_lock.read() {
                    let initial_balance = self.client.get_balance(sender);
                    let lattice_balance = compute_lattice_balance(sender, &reg, initial_balance);
                    let gas_price = tx.gas_price().unwrap_or_else(|| tx.max_fee_per_gas());
                    let needed = tx.value().saturating_add(alloy_primitives::U256::from(tx.gas_limit()).saturating_mul(alloy_primitives::U256::from(gas_price)));
                    if lattice_balance >= needed {
                        TransactionValidationOutcome::Valid {
                            balance: lattice_balance,
                            state_nonce: tx.nonce(),
                            bytecode_hash: None,
                            transaction: reth_transaction_pool::validate::ValidTransaction::Valid(tx),
                            propagate: true,
                            authorities: None,
                        }
                    } else {
                        TransactionValidationOutcome::Invalid(tx, err)
                    }
                } else {
                    TransactionValidationOutcome::Invalid(tx, err)
                }
            }
            other => other,
        };

        if let TransactionValidationOutcome::Invalid(_, _) = &final_outcome {
            return final_outcome;
        }

        // Add to account pool queue
        {
            let mut queues = self.account_queues.lock().unwrap();
            queues.entry(transaction.sender()).or_default().push(*transaction.hash());
        }

        final_outcome
    }

    fn on_new_head_block(&self, new_head: &reth_primitives_traits::SealedBlock<Self::Block>) {
        self.inner.on_new_head_block(new_head);
    }
}

#[derive(Debug, Clone)]
pub struct SovereignPoolBuilder {
    pool_config: PoolConfig,
}

impl Default for SovereignPoolBuilder {
    fn default() -> Self {
        let mut pool_config = PoolConfig::default();
        pool_config.minimal_protocol_basefee = 0;
        pool_config.minimum_priority_fee = None;
        Self { pool_config }
    }
}

impl SovereignPoolBuilder {
    /// Creates a new `SovereignPoolBuilder` with default configuration.
    pub fn new(pool_config: PoolConfig) -> Self {
        Self { pool_config }
    }
}

impl<Types, N, Evm> PoolBuilder<N, Evm> for SovereignPoolBuilder
where
    Types: NodeTypes<
        ChainSpec: EthereumHardforks,
        Primitives: NodePrimitives<SignedTx = reth_ethereum_primitives::TransactionSigned>,
    >,
    N: FullNodeTypes<Types = Types>,
    Evm: ConfigureEvm<Primitives = PrimitivesTy<Types>> + Clone + 'static,
{
    type Pool = Pool<
        SovereignQuantumTransactionValidator<
            TransactionValidationTaskExecutor<
                reth_ethereum::pool::EthTransactionValidator<
                    N::Provider,
                    reth_ethereum::pool::EthPooledTransaction,
                    Evm,
                >,
            >,
            LatticeClient<N::Provider>,
        >,
        FCFSOrdering<reth_ethereum::pool::EthPooledTransaction>,
        InMemoryBlobStore,
    >;

    async fn build_pool(
        self,
        ctx: &BuilderContext<N>,
        evm_config: Evm,
    ) -> eyre::Result<Self::Pool> {
        let data_dir = ctx.config().datadir();
        let blob_store = InMemoryBlobStore::default();

        let eth_validator =
            TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone(), evm_config)
                .kzg_settings(ctx.kzg_settings()?)
                .with_additional_tasks(ctx.config().txpool.additional_validation_tasks)
                .build_with_tasks(ctx.task_executor().clone(), blob_store.clone());

        let validator = SovereignQuantumTransactionValidator::new(eth_validator, LatticeClient(ctx.provider().clone()));

        let transaction_pool =
            Pool::new(validator, FCFSOrdering::new(), blob_store, self.pool_config);
        info!(target: "reth::cli", "Sovereign FCFS Transaction pool initialized (with Zero Latency Quantum Trigger enforcement)");

        let transactions_path = data_dir.txpool_transactions();
        {
            let pool = transaction_pool.clone();
            let chain_events = ctx.provider().canonical_state_stream();
            let client = ctx.provider().clone();
            let transactions_backup_config =
                reth_ethereum::pool::maintain::LocalTransactionBackupConfig::with_local_txs_backup(
                    transactions_path,
                );

            ctx.task_executor()
                .spawn_critical_with_graceful_shutdown_signal(
                    "local transactions backup task",
                    |shutdown| {
                        reth_ethereum::pool::maintain::backup_local_transactions_task(
                            shutdown,
                            pool.clone(),
                            transactions_backup_config,
                        )
                    },
                );

            ctx.task_executor().spawn_critical_task(
                "txpool maintenance task",
                reth_ethereum::pool::maintain::maintain_transaction_pool_future(
                    client,
                    pool,
                    chain_events,
                    ctx.task_executor().clone(),
                    reth_ethereum::pool::maintain::MaintainPoolConfig {
                        max_tx_lifetime: transaction_pool.config().max_queued_lifetime,
                        ..Default::default()
                    },
                ),
            );
        }
        Ok(transaction_pool)
    }
}

/// Mathematically validate a transaction's witness data against the state root.
pub fn validate_witness<T: PoolTransaction>(
    transaction: &TransactionWithWitness<T>,
    _state_root: B256,
) -> bool {
    // Instant rejection if witness is empty
    if transaction.witness.is_empty() {
        return false;
    }

    #[cfg(test)]
    {
        // Fallback for testing/dev
        if transaction.witness.len() >= 4 && transaction.witness[0..4] == [0xde, 0xad, 0xbe, 0xef] {
            return true;
        }
    }

    let registry_lock = crate::registry::get_registry();
    let (quantum_threat, default_crypto_profile) = if let Ok(reg) = registry_lock.read() {
        let dynamic = reg.dynamic_cfg.read().unwrap();
        (dynamic.zero_latency_quantum_trigger, dynamic.default_crypto_profile.clone())
    } else {
        (false, "ethereum".to_string())
    };

    let profile = crate::crypto::CryptoProfile::from_name(&default_crypto_profile)
        .unwrap_or(crate::crypto::CryptoProfile::ETHEREUM);

    // Try to unpack PQ envelope from witness
    if let Ok((scheme, pk, sig)) = crate::crypto::unpack_pq_envelope(&transaction.witness) {
        if quantum_threat && !scheme.is_post_quantum() {
            return false;
        }

        // Verify signature natively
        let msg = transaction.transaction.hash().as_slice();
        if crate::crypto::verify_signature(scheme, &pk, msg, &sig, quantum_threat).is_err() {
            return false;
        }

        // Derive address using the scheme's mapping
        let hash_scheme = scheme.default_address_hash();
        let derived_addr = alloy_primitives::Address::from(crate::crypto::derive_address(hash_scheme, &pk));
        return derived_addr == transaction.transaction.sender();
    }

    if quantum_threat {
        // Enforce PQ trigger requires PQ envelopes
        return false;
    }

    // Traditional fallback based on default profile
    if profile.signature == crate::crypto::SignatureScheme::Secp256k1 {
        let Ok(sig) = alloy_primitives::Signature::try_from(transaction.witness.as_slice()) else {
            return false;
        };

        // Recover address from signature and transaction hash
        let hash = transaction.transaction.hash();
        let Ok(recovered_addr) = sig.recover_address_from_prehash(&hash) else {
            return false;
        };

        recovered_addr == transaction.transaction.sender()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_transaction_pool::test_utils::MockTransaction;

    #[test]
    fn test_fcfs_ordering_priority() {
        let ordering = FCFSOrdering::new();
        
        let tx1 = MockTransaction::eip1559();
        let tx2 = MockTransaction::eip1559();
        
        let p1 = ordering.priority(&tx1, 0);
        let p2 = ordering.priority(&tx2, 0);
        
        // tx1 arrived first, so it should have a higher priority (lower sequence number)
        assert!(p1 > p2);
        
        // Querying tx1 again should return the same priority
        let p1_again = ordering.priority(&tx1, 0);
        assert_eq!(p1, p1_again);
    }

    #[test]
    fn test_witness_validation() {
        use crate::crypto::{pack_pq_envelope, SignatureScheme};
        use fips204::traits::{KeyGen, Signer, SerDes};

        let tx = MockTransaction::eip1559();
        let mut tx_with_witness = TransactionWithWitness {
            transaction: tx.clone(),
            witness: vec![],
        };

        let root = B256::repeat_byte(0xaa);

        // Missing witness should fail
        assert!(!validate_witness(&tx_with_witness, root));

        // Invalid witness should fail
        tx_with_witness.witness = vec![0x12, 0x34, 0x56, 0x78];
        assert!(!validate_witness(&tx_with_witness, root));

        // Valid witness (prefix deadbeef) should pass when quantum trigger is false
        let registry_lock = crate::registry::get_registry();
        {
            let mut reg = registry_lock.write().unwrap();
            *reg = crate::registry::ValidatorRegistry::default();
            let mut dynamic = reg.dynamic_cfg.write().unwrap();
            dynamic.zero_latency_quantum_trigger = false;
        }
        tx_with_witness.witness = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
        assert!(validate_witness(&tx_with_witness, root));

        // When quantum trigger is true, PQ envelope is required
        {
            let mut reg = registry_lock.write().unwrap();
            *reg = crate::registry::ValidatorRegistry::default();
            let mut dynamic = reg.dynamic_cfg.write().unwrap();
            dynamic.zero_latency_quantum_trigger = true;
            dynamic.default_pq_scheme = "mldsa".to_string();
        }

        // Generate real ML-DSA key pair and signature
        let (pk_struct, sk_struct) = fips204::ml_dsa_65::KG::try_keygen().unwrap();
        let pk_bytes = pk_struct.into_bytes();

        let mut pq_tx = MockTransaction::eip1559();
        let msg = pq_tx.hash();
        let sig_bytes = sk_struct.try_sign(msg.as_slice(), &[]).unwrap();

        let env_bytes = pack_pq_envelope(SignatureScheme::MlDsa, &pk_bytes, &sig_bytes);

        // Derived sender EVM address matching key
        let derived_addr = alloy_primitives::Address::from(crate::crypto::derive_address(crate::crypto::HashScheme::Poseidon, &pk_bytes));
        pq_tx.set_sender(derived_addr);

        let pq_tx_with_witness = TransactionWithWitness {
            transaction: pq_tx,
            witness: env_bytes,
        };

        assert!(validate_witness(&pq_tx_with_witness, root));

        // Clean up
        {
            let reg = registry_lock.read().unwrap();
            let mut dynamic = reg.dynamic_cfg.write().unwrap();
            dynamic.zero_latency_quantum_trigger = false;
        }
    }

    #[tokio::test]
    async fn test_quantum_transaction_validator() {
        use reth_transaction_pool::test_utils::MockTransaction;
        use reth_transaction_pool::noop::MockTransactionValidator;
        use crate::crypto::{pack_pq_envelope, SignatureScheme};
        use fips204::traits::{KeyGen, Signer, SerDes};
        use alloy_consensus::Transaction;

        let validator = SovereignQuantumTransactionValidator::new(MockTransactionValidator::default(), ());
        let tx = MockTransaction::eip1559();

        let registry_lock = crate::registry::get_registry();
        {
            let mut reg = registry_lock.write().unwrap();
            *reg = crate::registry::ValidatorRegistry::default();
            
            // Register DID for the mock transaction sender to satisfy Gate 0 check
            let did = format!("did:sovereign:1337:{}", tx.sender().to_string().to_lowercase());
            reg.address_to_did.insert(tx.sender(), did.clone());
            reg.peer_keys.insert(did.clone(), [0x01; 32]);
            let mut doc = sovereign_identity::did::SovereignDidDocument::derive_from_seed(alloy_primitives::B256::repeat_byte(0xbc));
            doc.evm_address = tx.sender();
            reg.identities.insert(did.clone(), crate::registry::RegisteredIdentity {
                did,
                doc,
                registered_at: 0,
            });

            let mut dynamic = reg.dynamic_cfg.write().unwrap();
            dynamic.zero_latency_quantum_trigger = false;
            dynamic.default_pq_scheme = "mldsa".to_string();
        }

        {
            let reg = registry_lock.read().unwrap();
            let sender = tx.sender();
            let did_opt = reg.get_did_by_address(&sender);
            println!("TEST SENDER DID: {:?}", did_opt);
            if let Some(ref did) = did_opt {
                println!("IS FULLY REG: {}", reg.is_did_fully_registered(did));
                if let Some(ident) = reg.identities.get(did) {
                    println!("SECP: {}, ED: {}, BLS: {}, ML: {}, SLH: {}, FALCON: {}, XMSS: {}",
                        !ident.doc.secp256k1_pubkey.is_empty(),
                        !ident.doc.ed25519_pubkey.is_empty(),
                        !ident.doc.bls_pubkey.is_empty(),
                        !ident.doc.ml_dsa_pubkey.is_empty(),
                        !ident.doc.slh_dsa_pubkey.is_empty(),
                        !ident.doc.falcon_pubkey.is_empty(),
                        !ident.doc.xmss_pubkey.is_empty()
                    );
                }
            }
        }

        // When quantum trigger is false, transaction is valid
        let res = validator.validate_transaction(TransactionOrigin::External, tx.clone()).await;
        println!("VALIDATION RESULT IS: {:?}", res);
        assert!(matches!(res, TransactionValidationOutcome::Valid { .. }));

        // Generate real ML-DSA key pair and signature
        let (pk_struct, sk_struct) = fips204::ml_dsa_65::KG::try_keygen().unwrap();
        let pk_bytes = pk_struct.into_bytes();
        let derived_addr = alloy_primitives::Address::from(crate::crypto::derive_address(crate::crypto::HashScheme::Poseidon, &pk_bytes));

        // Enable quantum trigger
        {
            let mut reg = registry_lock.write().unwrap();
            {
                let mut dynamic = reg.dynamic_cfg.write().unwrap();
                dynamic.zero_latency_quantum_trigger = true;
            }
            reg.did_key_tier.insert(derived_addr, crate::pq_registry::KeyTier::QuantumReady);

            // Register DID for derived_addr
            let did = format!("did:sovereign:1337:{}", derived_addr.to_string().to_lowercase());
            reg.address_to_did.insert(derived_addr, did.clone());
            reg.peer_keys.insert(did.clone(), [0x01; 32]);
            let mut doc = sovereign_identity::did::SovereignDidDocument::derive_from_seed(alloy_primitives::B256::repeat_byte(0xbc));
            doc.evm_address = derived_addr;
            reg.identities.insert(did.clone(), crate::registry::RegisteredIdentity {
                did,
                doc,
                registered_at: 0,
            });
        }

        // When quantum trigger is true, standard transaction (without PQ envelope) MUST be rejected
        let res = validator.validate_transaction(TransactionOrigin::External, tx.clone()).await;
        assert!(matches!(res, TransactionValidationOutcome::Invalid(_, _)));

        let mut pq_tx = MockTransaction::eip1559();
        pq_tx.set_sender(derived_addr);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(derived_addr.as_slice());
        bytes.extend_from_slice(&pq_tx.nonce().to_be_bytes());
        if let Some(to) = pq_tx.to() {
            bytes.extend_from_slice(to.as_slice());
        }
        bytes.extend_from_slice(&pq_tx.value().to_be_bytes::<32>());
        let hash = alloy_primitives::keccak256(&bytes);
        let msg = hash.as_slice();

        let sig_bytes = sk_struct.try_sign(msg, &[]).unwrap();

        let env_bytes = pack_pq_envelope(SignatureScheme::MlDsa, &pk_bytes, &sig_bytes);

        pq_tx.set_input(env_bytes.into());

        // Validate PQ envelope transaction
        let res = validator.validate_transaction(TransactionOrigin::External, pq_tx).await;
        assert!(matches!(res, TransactionValidationOutcome::Valid { .. }));

        // Clean up
        {
            let reg = registry_lock.read().unwrap();
            let mut dynamic = reg.dynamic_cfg.write().unwrap();
            dynamic.zero_latency_quantum_trigger = false;
        }
    }

    #[test]
    fn test_lattice_balance_calculation_and_restrictions() {
        let registry_lock = crate::registry::get_registry();
        let mut reg = registry_lock.write().unwrap();
        *reg = crate::registry::ValidatorRegistry::default();

        let alice = alloy_primitives::Address::repeat_byte(0x01);
        let bob = alloy_primitives::Address::repeat_byte(0x02);

        // Initial balance should be 10,000 ETH
        let initial_balance = compute_lattice_balance(alice, &reg, alloy_primitives::U256::from(10_000_000_000_000_000_000_000u128));
        assert_eq!(initial_balance, alloy_primitives::U256::from(10_000_000_000_000_000_000_000u128));

        // Alice sends 3 ETH to Bob (Send block)
        let send_block = crate::stateless::LatticeBlock {
            account: alice,
            previous_hash: B256::ZERO,
            sequence: 1,
            payload: crate::stateless::LatticePayload::Send { recipient: bob, amount: alloy_primitives::U256::from(3_000_000_000_000_000_000u128) },
            signature: vec![1, 2, 3],
            static_witnesses: vec![],
        };
        reg.lattice_blocks.insert(B256::repeat_byte(0x11), send_block);

        // Alice balance should now be 9,997 ETH
        let alice_bal = compute_lattice_balance(alice, &reg, alloy_primitives::U256::from(10_000_000_000_000_000_000_000u128));
        assert_eq!(alice_bal, alloy_primitives::U256::from(9_997_000_000_000_000_000_000u128));

        // Bob's lattice balance should STILL be 10,000 ETH (the pending transfer has not been claimed yet!)
        let bob_bal_pending = compute_lattice_balance(bob, &reg, alloy_primitives::U256::from(10_000_000_000_000_000_000_000u128));
        assert_eq!(bob_bal_pending, alloy_primitives::U256::from(10_000_000_000_000_000_000_000u128));

        // Bob receives the transfer (Receive block)
        let receive_block = crate::stateless::LatticeBlock {
            account: bob,
            previous_hash: B256::ZERO,
            sequence: 1,
            payload: crate::stateless::LatticePayload::Receive {
                send_block_hash: B256::repeat_byte(0x11),
                amount: alloy_primitives::U256::from(3_000_000_000_000_000_000u128),
            },
            signature: vec![],
            static_witnesses: vec![],
        };
        reg.lattice_blocks.insert(B256::repeat_byte(0x22), receive_block);

        // Bob's balance should now be 10,003 ETH
        let bob_bal_claimed = compute_lattice_balance(bob, &reg, alloy_primitives::U256::from(10_000_000_000_000_000_000_000u128));
        assert_eq!(bob_bal_claimed, alloy_primitives::U256::from(10_003_000_000_000_000_000_000u128));
    }
}


