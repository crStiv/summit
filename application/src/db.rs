use alloy_eips::eip4895::Withdrawal;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::store::{self, Store};
use commonware_storage::translator::TwoCap;
use commonware_utils::sequence::FixedBytes;
pub use store::Config;
use summit_types::execution_request::{DepositRequest, WithdrawalRequest};
use summit_types::withdrawal::PendingWithdrawal;

// Key prefixes for different data types
const STATE_PREFIX: u8 = 0x01;
const DEPOSIT_QUEUE_PREFIX: u8 = 0x02;
const WITHDRAWAL_QUEUE_PREFIX: u8 = 0x03;
const ACCOUNTS_PREFIX: u8 = 0x04;

// Queue pointer keys (using FixedBytes<64> to accommodate all key types)
const DEPOSIT_HEAD_KEY: [u8; 9] = [DEPOSIT_QUEUE_PREFIX, 0, 0, 0, 0, 0, 0, 0, 0];
const DEPOSIT_TAIL_KEY: [u8; 9] = [DEPOSIT_QUEUE_PREFIX, 0, 0, 0, 0, 0, 0, 0, 1];
const WITHDRAWAL_HEAD_KEY: [u8; 9] = [WITHDRAWAL_QUEUE_PREFIX, 0, 0, 0, 0, 0, 0, 0, 0];
const WITHDRAWAL_TAIL_KEY: [u8; 9] = [WITHDRAWAL_QUEUE_PREFIX, 0, 0, 0, 0, 0, 0, 0, 1];

// State variable keys
const LATEST_HEIGHT_KEY: [u8; 2] = [STATE_PREFIX, 0];
const NEXT_WITHDRAWAL_INDEX_KEY: [u8; 2] = [STATE_PREFIX, 1];

pub struct FinalizerState<E: Clock + Storage + Metrics> {
    store: Store<E, FixedBytes<64>, Value, TwoCap>,
}

impl<E: Clock + Storage + Metrics> FinalizerState<E> {
    pub async fn new(context: E, cfg: Config<TwoCap, ()>) -> Self {
        let mut store = Store::<_, FixedBytes<64>, Value, TwoCap>::init(context, cfg)
            .await
            .expect("failed to initialize unified store");

        // Initialize queue pointers if they don't exist
        let deposit_head_key = Self::pad_key(&DEPOSIT_HEAD_KEY);
        let deposit_tail_key = Self::pad_key(&DEPOSIT_TAIL_KEY);
        let withdrawal_head_key = Self::pad_key(&WITHDRAWAL_HEAD_KEY);
        let withdrawal_tail_key = Self::pad_key(&WITHDRAWAL_TAIL_KEY);
        let latest_height_key = Self::pad_key(&LATEST_HEIGHT_KEY);
        let next_withdrawal_index_key = Self::pad_key(&NEXT_WITHDRAWAL_INDEX_KEY);

        // Initialize deposit queue pointers
        if store
            .get(&deposit_head_key)
            .await
            .expect("failed to get deposit head")
            .is_none()
        {
            store
                .update(deposit_head_key, Value::U64(2))
                .await
                .expect("failed to initialize deposit head");
        }
        if store
            .get(&deposit_tail_key)
            .await
            .expect("failed to get deposit tail")
            .is_none()
        {
            store
                .update(deposit_tail_key, Value::U64(2))
                .await
                .expect("failed to initialize deposit tail");
        }

        // Initialize withdrawal queue pointers
        if store
            .get(&withdrawal_head_key)
            .await
            .expect("failed to get withdrawal head")
            .is_none()
        {
            store
                .update(withdrawal_head_key, Value::U64(2))
                .await
                .expect("failed to initialize withdrawal head");
        }
        if store
            .get(&withdrawal_tail_key)
            .await
            .expect("failed to get withdrawal tail")
            .is_none()
        {
            store
                .update(withdrawal_tail_key, Value::U64(2))
                .await
                .expect("failed to initialize withdrawal tail");
        }

        // Initialize latest height
        if store
            .get(&latest_height_key)
            .await
            .expect("failed to get latest height")
            .is_none()
        {
            store
                .update(latest_height_key, Value::U64(0))
                .await
                .expect("failed to initialize latest height");
        }

        // Initialize next withdrawal index
        if store
            .get(&next_withdrawal_index_key)
            .await
            .expect("failed to get next withdrawal index")
            .is_none()
        {
            store
                .update(next_withdrawal_index_key, Value::U64(0))
                .await
                .expect("failed to initialize next withdrawal index");
        }

        store
            .commit()
            .await
            .expect("failed to commit initialization");

        Self { store }
    }

    fn pad_key(key: &[u8]) -> FixedBytes<64> {
        let mut padded = [0u8; 64];
        let len = key.len().min(64);
        padded[..len].copy_from_slice(&key[..len]);
        FixedBytes::new(padded)
    }

    fn make_account_key(pubkey: &[u8; 48]) -> FixedBytes<64> {
        let mut key = [0u8; 64];
        key[0] = ACCOUNTS_PREFIX;
        key[1..49].copy_from_slice(pubkey);
        FixedBytes::new(key)
    }

    fn make_queue_key(prefix: u8, index: u64) -> FixedBytes<64> {
        let mut key = [0u8; 64];
        key[0] = prefix;
        key[1..9].copy_from_slice(&index.to_be_bytes());
        FixedBytes::new(key)
    }

    // State variables operations
    pub async fn get_latest_height(&self) -> u64 {
        let key = Self::pad_key(&LATEST_HEIGHT_KEY);
        if let Some(Value::U64(height)) = self
            .store
            .get(&key)
            .await
            .expect("failed to get latest height")
        {
            height
        } else {
            0
        }
    }

    pub async fn set_latest_height(&mut self, height: u64) {
        let key = Self::pad_key(&LATEST_HEIGHT_KEY);
        self.store
            .update(key, Value::U64(height))
            .await
            .expect("failed to set latest height");
        self.store
            .commit()
            .await
            .expect("failed to commit latest height");
    }

    async fn get_and_increment_withdrawal_index(&mut self) -> u64 {
        let key = Self::pad_key(&NEXT_WITHDRAWAL_INDEX_KEY);
        let current = if let Some(Value::U64(index)) = self
            .store
            .get(&key)
            .await
            .expect("failed to get withdrawal index")
        {
            index
        } else {
            0
        };
        self.store
            .update(key, Value::U64(current + 1))
            .await
            .expect("failed to update withdrawal index");
        current
    }

    // Account operations
    pub async fn get_account(&self, pubkey: &[u8; 48]) -> Option<DepositRequest> {
        let key = Self::make_account_key(pubkey);

        if let Some(Value::DepositRequest(account)) =
            self.store.get(&key).await.expect("failed to get account")
        {
            Some(account)
        } else {
            None
        }
    }

    pub async fn set_account(&mut self, pubkey: &[u8; 48], account: DepositRequest) {
        let key = Self::make_account_key(pubkey);

        self.store
            .update(key, Value::DepositRequest(account))
            .await
            .expect("failed to set account");
    }

    // Deposit queue operations
    async fn get_deposit_head(&self) -> u64 {
        let key = Self::pad_key(&DEPOSIT_HEAD_KEY);
        if let Some(Value::U64(head)) = self
            .store
            .get(&key)
            .await
            .expect("failed to get deposit head")
        {
            head
        } else {
            2 // Default starting position
        }
    }

    async fn get_deposit_tail(&self) -> u64 {
        let key = Self::pad_key(&DEPOSIT_TAIL_KEY);
        if let Some(Value::U64(tail)) = self
            .store
            .get(&key)
            .await
            .expect("failed to get deposit tail")
        {
            tail
        } else {
            2 // Default starting position
        }
    }

    async fn update_deposit_head(&mut self, value: u64) {
        let key = Self::pad_key(&DEPOSIT_HEAD_KEY);
        self.store
            .update(key, Value::U64(value))
            .await
            .expect("failed to update deposit head");
    }

    async fn update_deposit_tail(&mut self, value: u64) {
        let key = Self::pad_key(&DEPOSIT_TAIL_KEY);
        self.store
            .update(key, Value::U64(value))
            .await
            .expect("failed to update deposit tail");
    }

    pub async fn push_deposit(&mut self, request: DepositRequest) {
        let tail_value = self.get_deposit_tail().await;

        let key = Self::make_queue_key(DEPOSIT_QUEUE_PREFIX, tail_value);

        self.store
            .update(key, Value::DepositRequest(request))
            .await
            .expect("failed to store deposit");
        self.update_deposit_tail(tail_value + 1).await;
    }

    pub async fn peek_deposit(&self) -> Option<DepositRequest>
    where
        DepositRequest: Clone,
    {
        let head_value = self.get_deposit_head().await;
        let tail_value = self.get_deposit_tail().await;

        if head_value >= tail_value {
            return None;
        }

        let key = Self::make_queue_key(DEPOSIT_QUEUE_PREFIX, head_value);

        if let Some(Value::DepositRequest(request)) =
            self.store.get(&key).await.expect("failed to peek deposit")
        {
            Some(request.clone())
        } else {
            None
        }
    }

    pub async fn pop_deposit(&mut self) -> Option<DepositRequest> {
        let head_value = self.get_deposit_head().await;
        let tail_value = self.get_deposit_tail().await;

        if head_value >= tail_value {
            return None;
        }

        let key = Self::make_queue_key(DEPOSIT_QUEUE_PREFIX, head_value);

        let result = if let Some(Value::DepositRequest(request)) =
            self.store.get(&key).await.expect("failed to get deposit")
        {
            Some(request)
        } else {
            None
        };

        if result.is_some() {
            self.store
                .delete(key)
                .await
                .expect("failed to delete deposit");

            let new_head = head_value + 1;
            if new_head == tail_value {
                // Queue becomes empty, reset pointers
                self.update_deposit_head(2).await;
                self.update_deposit_tail(2).await;
            } else {
                self.update_deposit_head(new_head).await;
            }

            //self.store.commit().await.expect("failed to commit deposit pop");
        }

        result
    }

    // Withdrawal queue operations (similar to deposit queue)
    async fn get_withdrawal_head(&self) -> u64 {
        let key = Self::pad_key(&WITHDRAWAL_HEAD_KEY);
        if let Some(Value::U64(head)) = self
            .store
            .get(&key)
            .await
            .expect("failed to get withdrawal head")
        {
            head
        } else {
            2
        }
    }

    async fn get_withdrawal_tail(&self) -> u64 {
        let key = Self::pad_key(&WITHDRAWAL_TAIL_KEY);
        if let Some(Value::U64(tail)) = self
            .store
            .get(&key)
            .await
            .expect("failed to get withdrawal tail")
        {
            tail
        } else {
            2
        }
    }

    async fn update_withdrawal_head(&mut self, value: u64) {
        let key = Self::pad_key(&WITHDRAWAL_HEAD_KEY);
        self.store
            .update(key, Value::U64(value))
            .await
            .expect("failed to update withdrawal head");
    }

    async fn update_withdrawal_tail(&mut self, value: u64) {
        let key = Self::pad_key(&WITHDRAWAL_TAIL_KEY);
        self.store
            .update(key, Value::U64(value))
            .await
            .expect("failed to update withdrawal tail");
    }

    pub async fn push_withdrawal_request(
        &mut self,
        request: WithdrawalRequest,
        withdrawal_height: u64,
    ) {
        // Get the next unique withdrawal index
        let withdrawal_index = self.get_and_increment_withdrawal_index().await;

        // Convert WithdrawalRequest to PendingWithdrawal
        let pending_withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: withdrawal_index,
                validator_index: 0, // TODO: Map validator_pubkey to validator_index if needed
                address: request.source_address,
                amount: request.amount,
            },
            withdrawal_height,
            bls_pubkey: request.validator_pubkey,
        };

        self.push_withdrawal(pending_withdrawal).await;
    }

    pub async fn push_withdrawal(&mut self, request: PendingWithdrawal) {
        let tail_value = self.get_withdrawal_tail().await;

        let key = Self::make_queue_key(WITHDRAWAL_QUEUE_PREFIX, tail_value);

        self.store
            .update(key, Value::PendingWithdrawal(request))
            .await
            .expect("failed to store withdrawal");
        self.update_withdrawal_tail(tail_value + 1).await;
    }

    pub async fn peek_withdrawal(&self) -> Option<PendingWithdrawal>
    where
        PendingWithdrawal: Clone,
    {
        let head_value = self.get_withdrawal_head().await;
        let tail_value = self.get_withdrawal_tail().await;

        if head_value >= tail_value {
            return None;
        }

        let key = Self::make_queue_key(WITHDRAWAL_QUEUE_PREFIX, head_value);

        if let Some(Value::PendingWithdrawal(request)) = self
            .store
            .get(&key)
            .await
            .expect("failed to peek withdrawal")
        {
            Some(request.clone())
        } else {
            None
        }
    }

    pub async fn pop_withdrawal(&mut self) -> Option<PendingWithdrawal> {
        let head_value = self.get_withdrawal_head().await;
        let tail_value = self.get_withdrawal_tail().await;

        if head_value >= tail_value {
            return None;
        }

        let key = Self::make_queue_key(WITHDRAWAL_QUEUE_PREFIX, head_value);

        let result = if let Some(Value::PendingWithdrawal(request)) = self
            .store
            .get(&key)
            .await
            .expect("failed to get withdrawal")
        {
            Some(request)
        } else {
            None
        };

        if result.is_some() {
            self.store
                .delete(key)
                .await
                .expect("failed to delete withdrawal");

            let new_head = head_value + 1;
            if new_head == tail_value {
                self.update_withdrawal_head(2).await;
                self.update_withdrawal_tail(2).await;
            } else {
                self.update_withdrawal_head(new_head).await;
            }

            //self.store.commit().await.expect("failed to commit withdrawal pop");
        }

        result
    }

    /// Get the next K pending withdrawals that are ready for processing at the given block height.
    /// Only returns withdrawals where withdrawal_height <= block_height.
    pub async fn get_next_ready_withdrawals(
        &self,
        block_height: u64,
        k: usize,
    ) -> Vec<PendingWithdrawal>
    where
        PendingWithdrawal: Clone,
    {
        let mut ready_withdrawals = Vec::new();
        let head_value = self.get_withdrawal_head().await;
        let tail_value = self.get_withdrawal_tail().await;

        let mut current = head_value;
        while current < tail_value && ready_withdrawals.len() < k {
            let key = Self::make_queue_key(WITHDRAWAL_QUEUE_PREFIX, current);

            if let Some(Value::PendingWithdrawal(withdrawal)) = self
                .store
                .get(&key)
                .await
                .expect("failed to get withdrawal")
            {
                // Only include withdrawals that are ready (withdrawal_height <= block_height)
                if withdrawal.withdrawal_height <= block_height {
                    ready_withdrawals.push(withdrawal.clone());
                } else {
                    // Since withdrawals are stored in FIFO order, if this one isn't ready,
                    // none of the subsequent ones will be ready either
                    break;
                }
            }

            current += 1;
        }

        ready_withdrawals
    }
}

#[derive(Clone)]
enum Value {
    U64(u64),
    DepositRequest(DepositRequest),
    PendingWithdrawal(PendingWithdrawal),
}

impl EncodeSize for Value {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::U64(_) => 8,
            Self::DepositRequest(req) => req.encode_size(),
            Self::PendingWithdrawal(req) => req.encode_size(),
        }
    }
}

impl Read for Value {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let value_type = buf.get_u8();
        match value_type {
            0x01 => Ok(Self::U64(buf.get_u64())),
            0x02 => Ok(Self::DepositRequest(DepositRequest::read_cfg(buf, &())?)),
            0x03 => Ok(Self::PendingWithdrawal(PendingWithdrawal::read_cfg(
                buf,
                &(),
            )?)),
            byte => Err(Error::InvalidVarint(byte as usize)),
        }
    }
}

impl Write for Value {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::U64(val) => {
                buf.put_u8(0x01);
                buf.put_u64(*val);
            }
            Self::DepositRequest(req) => {
                buf.put_u8(0x02);
                req.write(buf);
            }
            Self::PendingWithdrawal(req) => {
                buf.put_u8(0x03);
                req.write(buf);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip4895::Withdrawal;
    use alloy_primitives::Address;
    use commonware_codec::DecodeExt;
    use commonware_runtime::buffer::PoolRef;
    use commonware_runtime::{Runner as _, deterministic::Runner};
    use commonware_utils::{NZU64, NZUsize};
    use summit_types::PublicKey;
    use summit_types::execution_request::{DepositRequest, WithdrawalRequest};
    use summit_types::withdrawal::PendingWithdrawal;

    async fn create_test_db_with_context<E: Clock + Storage + Metrics>(
        partition: &str,
        context: E,
    ) -> FinalizerState<E> {
        let config = Config {
            log_journal_partition: format!("{}-log", partition),
            log_write_buffer: NZUsize!(64 * 1024),
            log_compression: None,
            log_codec_config: (),
            log_items_per_section: NZU64!(4),
            locations_journal_partition: format!("{}-locations", partition),
            locations_items_per_blob: NZU64!(4),
            translator: TwoCap,
            buffer_pool: PoolRef::new(NZUsize!(77), NZUsize!(9)),
        };
        FinalizerState::new(context, config).await
    }

    fn create_test_deposit_request(index: u64, amount: u64) -> DepositRequest {
        // Use the exact same pattern as the working tests - just [1u8; 32] for all keys
        // since this is test data and we only need it to be valid, not unique
        DepositRequest {
            bls_pubkey: [index as u8; 48],
            ed25519_pubkey: PublicKey::decode(&[1u8; 32][..]).unwrap(),
            withdrawal_credentials: [index as u8; 32],
            amount,
            signature: [index as u8; 96],
            index,
        }
    }

    fn create_test_withdrawal_request(index: u64, amount: u64) -> PendingWithdrawal {
        PendingWithdrawal {
            inner: Withdrawal {
                index,
                validator_index: index * 10, // Some different value
                address: Address::from([index as u8; 20]),
                amount,
            },
            withdrawal_height: index * 100, // Some height value
            bls_pubkey: [index as u8; 48], // Use index as bls_pubkey pattern
        }
    }

    #[test]
    fn test_state_variables() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(1);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db = create_test_db_with_context("test_state", context).await;

            // Test initial height is 0
            assert_eq!(db.get_latest_height().await, 0);

            // Test setting and getting height
            db.set_latest_height(42).await;
            assert_eq!(db.get_latest_height().await, 42);

            // Test updating height
            db.set_latest_height(100).await;
            assert_eq!(db.get_latest_height().await, 100);
        });
    }

    #[test]
    fn test_account_operations() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(2);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db = create_test_db_with_context("test_accounts", context).await;

            let pubkey = [1u8; 48];
            let deposit_req = create_test_deposit_request(1, 32000000000); // 32 ETH in gwei

            // Test account doesn't exist initially
            assert!(db.get_account(&pubkey).await.is_none());

            // Test setting account
            db.set_account(&pubkey, deposit_req.clone()).await;

            // Test getting account
            let retrieved = db.get_account(&pubkey).await;
            assert!(retrieved.is_some());
            let retrieved = retrieved.unwrap();
            assert_eq!(retrieved.bls_pubkey, pubkey);
            assert_eq!(retrieved.amount, 32000000000);
            assert_eq!(retrieved.index, 1);

            // Test updating account
            let updated_req = create_test_deposit_request(1, 64000000000); // 64 ETH
            db.set_account(&pubkey, updated_req).await;
            let retrieved = db.get_account(&pubkey).await.unwrap();
            assert_eq!(retrieved.amount, 64000000000);
        });
    }

    #[test]
    fn test_deposit_queue_empty() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(3);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db = create_test_db_with_context("test_deposit_empty", context).await;

            // Test empty queue operations
            assert!(db.peek_deposit().await.is_none());
            assert!(db.pop_deposit().await.is_none());
        });
    }

    #[test]
    fn test_deposit_queue_single_item() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(4);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db = create_test_db_with_context("test_deposit_single", context).await;

            let deposit_req = create_test_deposit_request(1, 32000000000);

            // Push item
            db.push_deposit(deposit_req.clone()).await;

            // Peek should return the item without removing it
            let peeked = db.peek_deposit().await;
            assert!(peeked.is_some());
            assert_eq!(peeked.unwrap().index, 1);

            // Peek again should return same item
            let peeked_again = db.peek_deposit().await;
            assert!(peeked_again.is_some());
            assert_eq!(peeked_again.unwrap().index, 1);

            // Pop should return and remove the item
            let popped = db.pop_deposit().await;
            assert!(popped.is_some());
            assert_eq!(popped.unwrap().index, 1);

            // Queue should now be empty
            assert!(db.peek_deposit().await.is_none());
            assert!(db.pop_deposit().await.is_none());
        });
    }

    #[test]
    fn test_deposit_queue_multiple_items() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(5);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db = create_test_db_with_context("test_deposit_multiple", context).await;

            // Push multiple items
            let req1 = create_test_deposit_request(1, 32000000000);
            let req2 = create_test_deposit_request(2, 32000000000);
            let req3 = create_test_deposit_request(3, 32000000000);

            db.push_deposit(req1).await;
            db.push_deposit(req2).await;
            db.push_deposit(req3).await;

            // Pop in FIFO order
            assert_eq!(db.pop_deposit().await.unwrap().index, 1);
            assert_eq!(db.pop_deposit().await.unwrap().index, 2);
            assert_eq!(db.pop_deposit().await.unwrap().index, 3);

            // Queue should be empty
            assert!(db.pop_deposit().await.is_none());
        });
    }

    #[test]
    fn test_withdrawal_queue_empty() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(6);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db = create_test_db_with_context("test_withdrawal_empty", context).await;

            // Test empty queue operations
            assert!(db.peek_withdrawal().await.is_none());
            assert!(db.pop_withdrawal().await.is_none());
        });
    }

    #[test]
    fn test_withdrawal_queue_operations() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(7);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db = create_test_db_with_context("test_withdrawal_ops", context).await;

            let withdrawal_req1 = create_test_withdrawal_request(1, 16000000000); // 16 ETH
            let withdrawal_req2 = create_test_withdrawal_request(2, 24000000000); // 24 ETH

            // Push items
            db.push_withdrawal(withdrawal_req1.clone()).await;
            db.push_withdrawal(withdrawal_req2.clone()).await;

            // Peek should return first item
            let peeked = db.peek_withdrawal().await;
            assert!(peeked.is_some());
            assert_eq!(peeked.unwrap().inner.amount, 16000000000);

            // Pop should return items in FIFO order
            let popped1 = db.pop_withdrawal().await;
            assert!(popped1.is_some());
            assert_eq!(popped1.unwrap().inner.amount, 16000000000);

            let popped2 = db.pop_withdrawal().await;
            assert!(popped2.is_some());
            assert_eq!(popped2.unwrap().inner.amount, 24000000000);

            // Queue should be empty
            assert!(db.peek_withdrawal().await.is_none());
            assert!(db.pop_withdrawal().await.is_none());
        });
    }

    #[test]
    fn test_mixed_operations() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(8);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db = create_test_db_with_context("test_mixed", context).await;

            // Test that different data types don't interfere
            let pubkey = [42u8; 48];
            let deposit_req = create_test_deposit_request(1, 32000000000);
            let withdrawal_req = create_test_withdrawal_request(1, 16000000000);

            // Set state variable
            db.set_latest_height(100).await;

            // Set account
            db.set_account(&pubkey, deposit_req.clone()).await;

            // Push to both queues
            db.push_deposit(deposit_req.clone()).await;
            db.push_withdrawal(withdrawal_req.clone()).await;

            // Verify all operations work independently
            assert_eq!(db.get_latest_height().await, 100);

            let account = db.get_account(&pubkey).await;
            assert!(account.is_some());
            assert_eq!(account.unwrap().amount, 32000000000);

            let deposit_peeked = db.peek_deposit().await;
            assert!(deposit_peeked.is_some());
            assert_eq!(deposit_peeked.unwrap().amount, 32000000000);

            let withdrawal_peeked = db.peek_withdrawal().await;
            assert!(withdrawal_peeked.is_some());
            assert_eq!(withdrawal_peeked.unwrap().inner.amount, 16000000000);
        });
    }

    #[test]
    fn test_get_next_ready_withdrawals() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(9);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut db = create_test_db_with_context("test_ready_withdrawals", context).await;

            // Add withdrawals with different withdrawal heights
            let withdrawal1 = PendingWithdrawal {
                inner: Withdrawal {
                    index: 1,
                    validator_index: 10,
                    address: Address::from([1u8; 20]),
                    amount: 16000000000,
                },
                withdrawal_height: 100, // Ready at height 100
                bls_pubkey: [1u8; 48],
            };

            let withdrawal2 = PendingWithdrawal {
                inner: Withdrawal {
                    index: 2,
                    validator_index: 20,
                    address: Address::from([2u8; 20]),
                    amount: 24000000000,
                },
                withdrawal_height: 150, // Ready at height 150
                bls_pubkey: [2u8; 48],
            };

            let withdrawal3 = PendingWithdrawal {
                inner: Withdrawal {
                    index: 3,
                    validator_index: 30,
                    address: Address::from([3u8; 20]),
                    amount: 32000000000,
                },
                withdrawal_height: 200, // Ready at height 200
                bls_pubkey: [3u8; 48],
            };

            db.push_withdrawal(withdrawal1.clone()).await;
            db.push_withdrawal(withdrawal2.clone()).await;
            db.push_withdrawal(withdrawal3.clone()).await;

            // Test: At height 50, no withdrawals should be ready
            let ready = db.get_next_ready_withdrawals(50, 10).await;
            assert_eq!(ready.len(), 0);

            // Test: At height 100, only withdrawal1 should be ready
            let ready = db.get_next_ready_withdrawals(100, 10).await;
            assert_eq!(ready.len(), 1);
            assert_eq!(ready[0].inner.index, 1);

            // Test: At height 150, withdrawal1 and withdrawal2 should be ready
            let ready = db.get_next_ready_withdrawals(150, 10).await;
            assert_eq!(ready.len(), 2);
            assert_eq!(ready[0].inner.index, 1);
            assert_eq!(ready[1].inner.index, 2);

            // Test: At height 200, all withdrawals should be ready
            let ready = db.get_next_ready_withdrawals(200, 10).await;
            assert_eq!(ready.len(), 3);
            assert_eq!(ready[0].inner.index, 1);
            assert_eq!(ready[1].inner.index, 2);
            assert_eq!(ready[2].inner.index, 3);

            // Test: Limit k=2, should only return first 2
            let ready = db.get_next_ready_withdrawals(200, 2).await;
            assert_eq!(ready.len(), 2);
            assert_eq!(ready[0].inner.index, 1);
            assert_eq!(ready[1].inner.index, 2);
        });
    }

    #[test]
    fn test_persistence_across_recreations() {
        use commonware_runtime::tokio;
        use std::{env, fs};

        let db_path = env::temp_dir().join("unified_db_test_unique");

        // Clean up any existing data
        if db_path.exists() {
            fs::remove_dir_all(&db_path).ok();
        }

        // First phase: Create db, add data, and close
        {
            let cfg = tokio::Config::default().with_storage_directory(db_path.clone());
            let executor = tokio::Runner::new(cfg);

            executor.start(|context| async move {
                let mut db = create_test_db_with_context("test_persistence_unique", context).await;

                // Add test data
                db.set_latest_height(42).await;

                let pubkey = [1u8; 48];
                let deposit_req = create_test_deposit_request(1, 32000000000);
                db.set_account(&pubkey, deposit_req.clone()).await;

                db.push_deposit(create_test_deposit_request(2, 16000000000))
                    .await;
                db.push_withdrawal(create_test_withdrawal_request(1, 8000000000))
                    .await;

                // Commit all changes
                db.store.commit().await.expect("failed to commit test data");

                // Verify data is there
                assert_eq!(db.get_latest_height().await, 42);
                assert!(db.get_account(&pubkey).await.is_some());
                assert!(db.peek_deposit().await.is_some());
                assert!(db.peek_withdrawal().await.is_some());
            });
        } // Database closes here when executor drops

        // Second phase: Recreate db with same path and verify data persists
        {
            let cfg = tokio::Config::default().with_storage_directory(db_path.clone());
            let executor = tokio::Runner::new(cfg);

            executor.start(|context| async move {
                let mut db = create_test_db_with_context("test_persistence_unique", context).await;

                // Verify persisted data is still there
                assert_eq!(db.get_latest_height().await, 42);

                let pubkey = [1u8; 48];
                let account = db.get_account(&pubkey).await;
                assert!(account.is_some());
                assert_eq!(account.unwrap().amount, 32000000000);

                let deposit = db.peek_deposit().await;
                assert!(deposit.is_some());
                assert_eq!(deposit.unwrap().amount, 16000000000);

                let withdrawal = db.peek_withdrawal().await;
                assert!(withdrawal.is_some());
                assert_eq!(withdrawal.unwrap().inner.amount, 8000000000);

                // Verify operations still work
                db.set_latest_height(100).await;
                assert_eq!(db.get_latest_height().await, 100);

                assert_eq!(db.pop_deposit().await.unwrap().amount, 16000000000);
                assert_eq!(db.pop_withdrawal().await.unwrap().inner.amount, 8000000000);
            });
        }

        // Clean up test data
        if db_path.exists() {
            fs::remove_dir_all(&db_path).ok();
        }
    }
}
