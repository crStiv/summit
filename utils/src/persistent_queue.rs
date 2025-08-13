use commonware_codec::Codec;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::sequence::FixedBytes;

pub use metadata::Config;

const HEAD_KEY: [u8; 1] = [0; 1];
const TAIL_KEY: [u8; 1] = [1; 1];

pub struct PersistentQueue<E: Clock + Storage + Metrics, V: Codec> {
    // Store head/tail pointers
    pointers: Metadata<E, FixedBytes<1>, FixedBytes<8>>,
    // Store actual queue values with keys (sequence numbers)
    values: Metadata<E, FixedBytes<8>, V>,
}

impl<E: Clock + Storage + Metrics, V: Codec> PersistentQueue<E, V> {
    pub async fn new(context: E, cfg: Config<V::Cfg>) -> Self {
        let mut pointers: Metadata<E, FixedBytes<1>, FixedBytes<8>> = Metadata::init(
            context.with_label("pointers"),
            Config {
                partition: format!("{}-pointers", cfg.partition),
                codec_config: (),
            },
        )
        .await
        .expect("failed to initialize pointers metadata");

        pointers.put(
            FixedBytes::new(HEAD_KEY),
            FixedBytes::new(0u64.to_be_bytes()),
        );
        pointers.put(
            FixedBytes::new(TAIL_KEY),
            FixedBytes::new(0u64.to_be_bytes()),
        );

        let values: Metadata<E, FixedBytes<8>, V> = Metadata::init(
            context,
            Config {
                partition: format!("{}-values", cfg.partition),
                codec_config: cfg.codec_config,
            },
        )
        .await
        .expect("failed to initialize finalizer values metadata");

        Self { pointers, values }
    }

    pub fn push(&mut self, value: V) {
        let tail_key = self
            .pointers
            .get(&FixedBytes::new(TAIL_KEY))
            .expect("value is set on init");
        let tail_value = u64::from_be_bytes(tail_key.as_ref().try_into().expect("8 bytes"));

        // Store the value at the tail position
        self.values.put(tail_key.clone(), value);

        // Increment tail pointer
        let new_tail = tail_value + 1;
        self.pointers.put(
            FixedBytes::new(TAIL_KEY),
            FixedBytes::new(new_tail.to_be_bytes()),
        );
    }

    pub fn pop(&mut self) -> Option<V> {
        let head_key = self
            .pointers
            .get(&FixedBytes::new(HEAD_KEY))
            .expect("value is set on init");
        let tail_key = self
            .pointers
            .get(&FixedBytes::new(TAIL_KEY))
            .expect("value is set on init");

        let head_value = u64::from_be_bytes(head_key.as_ref().try_into().expect("8 bytes"));
        let tail_value = u64::from_be_bytes(tail_key.as_ref().try_into().expect("8 bytes"));

        // Check if queue is empty
        if head_value == tail_value {
            return None;
        }

        if let Some(value) = self.values.remove(head_key) {
            //increment head pointer
            let new_head = head_value + 1;

            // If queue becomes empty after this pop, reset pointers to 0
            if new_head == tail_value {
                self.pointers.put(
                    FixedBytes::new(HEAD_KEY),
                    FixedBytes::new(0u64.to_be_bytes()),
                );
                self.pointers.put(
                    FixedBytes::new(TAIL_KEY),
                    FixedBytes::new(0u64.to_be_bytes()),
                );
            } else {
                self.pointers.put(
                    FixedBytes::new(HEAD_KEY),
                    FixedBytes::new(new_head.to_be_bytes()),
                );
            }

            Some(value)
        } else {
            None
        }
    }

    pub fn is_empty(&self) -> bool {
        let head_key = self
            .pointers
            .get(&FixedBytes::new(HEAD_KEY))
            .expect("value is set on init");
        let tail_key = self
            .pointers
            .get(&FixedBytes::new(TAIL_KEY))
            .expect("value is set on init");

        let head_value = u64::from_be_bytes(head_key.as_ref().try_into().expect("8 bytes"));
        let tail_value = u64::from_be_bytes(tail_key.as_ref().try_into().expect("8 bytes"));

        head_value == tail_value
    }

    pub fn len(&self) -> usize {
        let head_key = self
            .pointers
            .get(&FixedBytes::new(HEAD_KEY))
            .expect("value is set on init");
        let tail_key = self
            .pointers
            .get(&FixedBytes::new(TAIL_KEY))
            .expect("value is set on init");

        let head_value = u64::from_be_bytes(head_key.as_ref().try_into().expect("8 bytes"));
        let tail_value = u64::from_be_bytes(tail_key.as_ref().try_into().expect("8 bytes"));

        (tail_value - head_value) as usize
    }

    pub fn peek(&self) -> Option<&V> {
        let head_key = self
            .pointers
            .get(&FixedBytes::new(HEAD_KEY))
            .expect("value is set on init");
        let tail_key = self
            .pointers
            .get(&FixedBytes::new(TAIL_KEY))
            .expect("value is set on init");

        let head_value = u64::from_be_bytes(head_key.as_ref().try_into().expect("8 bytes"));
        let tail_value = u64::from_be_bytes(tail_key.as_ref().try_into().expect("8 bytes"));

        // Check if queue is empty
        if head_value == tail_value {
            return None;
        }

        // Use get() instead of remove() to peek without removing
        self.values.get(&head_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{
        Runner as _,
        deterministic::{Context, Runner},
    };

    async fn create_test_queue_with_context(
        partition: &str,
        context: Context,
    ) -> PersistentQueue<Context, u32> {
        let config = Config {
            partition: partition.to_string(),
            codec_config: (),
        };
        PersistentQueue::new(context, config).await
    }

    #[test]
    fn test_new_queue_is_empty() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(1);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let queue = create_test_queue_with_context("test_new", context).await;

            assert!(queue.is_empty());
            assert_eq!(queue.len(), 0);
        });
    }

    #[test]
    fn test_push_single_item() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(2);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_push_single", context).await;

            queue.push(42);

            assert!(!queue.is_empty());
            assert_eq!(queue.len(), 1);
        });
    }

    #[test]
    fn test_push_pop_single_item() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(3);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_push_pop_single", context).await;

            queue.push(42);
            let popped = queue.pop();

            assert_eq!(popped, Some(42));
            assert!(queue.is_empty());
            assert_eq!(queue.len(), 0);
        });
    }

    #[test]
    fn test_push_pop_multiple_items() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(4);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_push_pop_multiple", context).await;

            // Push multiple items
            queue.push(1);
            queue.push(2);
            queue.push(3);

            assert_eq!(queue.len(), 3);

            // Pop them in FIFO order
            assert_eq!(queue.pop(), Some(1));
            assert_eq!(queue.len(), 2);

            assert_eq!(queue.pop(), Some(2));
            assert_eq!(queue.len(), 1);

            assert_eq!(queue.pop(), Some(3));
            assert_eq!(queue.len(), 0);
            assert!(queue.is_empty());
        });
    }

    #[test]
    fn test_pop_empty_queue() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(5);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_pop_empty", context).await;

            // Pop from empty queue should return None
            let popped = queue.pop();
            assert_eq!(popped, None);

            // Queue should still be empty
            assert!(queue.is_empty());
            assert_eq!(queue.len(), 0);
        });
    }

    #[test]
    fn test_pointer_reset_on_empty() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(6);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_pointer_reset", context).await;

            // Push some items to advance pointers
            queue.push(10);
            queue.push(20);
            queue.push(30);

            // Pop all items - this should reset pointers to 0
            assert_eq!(queue.pop(), Some(10));
            assert_eq!(queue.pop(), Some(20));
            assert_eq!(queue.pop(), Some(30)); // This should trigger pointer reset

            // Queue should be empty
            assert!(queue.is_empty());
            assert_eq!(queue.len(), 0);

            // Push new item should start from 0 again
            queue.push(40);
            assert_eq!(queue.len(), 1);
            assert_eq!(queue.pop(), Some(40));
        });
    }

    #[test]
    fn test_peek_empty_queue() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(7);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let queue = create_test_queue_with_context("test_peek_empty", context).await;

            // Peek empty queue should return None
            assert_eq!(queue.peek(), None);
            assert!(queue.is_empty());
            assert_eq!(queue.len(), 0);
        });
    }

    #[test]
    fn test_peek_single_item() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(8);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_peek_single", context).await;

            queue.push(42);

            // Peek should return the item
            assert_eq!(queue.peek(), Some(&42));
            // Queue should remain unchanged
            assert!(!queue.is_empty());
            assert_eq!(queue.len(), 1);
            
            // Multiple peeks should return same value
            assert_eq!(queue.peek(), Some(&42));
            assert_eq!(queue.peek(), Some(&42));
            assert_eq!(queue.len(), 1);
        });
    }

    #[test]
    fn test_peek_multiple_items() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(9);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_peek_multiple", context).await;

            queue.push(1);
            queue.push(2);
            queue.push(3);

            // Peek should return first item (FIFO)
            assert_eq!(queue.peek(), Some(&1));
            assert_eq!(queue.len(), 3);
            
            // Multiple peeks should return same value
            assert_eq!(queue.peek(), Some(&1));
            assert_eq!(queue.peek(), Some(&1));
            assert_eq!(queue.len(), 3);
        });
    }

    #[test]
    fn test_peek_pop_consistency() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(10);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_peek_pop_consistency", context).await;

            queue.push(100);
            queue.push(200);

            // Peek and pop should return same value
            assert_eq!(queue.peek(), Some(&100));
            assert_eq!(queue.pop(), Some(100));
            
            // Next peek should return next item
            assert_eq!(queue.peek(), Some(&200));
            assert_eq!(queue.pop(), Some(200));
            
            // Queue should be empty
            assert_eq!(queue.peek(), None);
            assert_eq!(queue.pop(), None);
            assert!(queue.is_empty());
        });
    }

    #[test]
    fn test_peek_after_operations() {
        let cfg = commonware_runtime::deterministic::Config::default().with_seed(11);
        let executor = Runner::from(cfg);
        executor.start(|context| async move {
            let mut queue = create_test_queue_with_context("test_peek_after_ops", context).await;

            // Initial peek on empty queue
            assert_eq!(queue.peek(), None);

            // Push and peek
            queue.push(10);
            assert_eq!(queue.peek(), Some(&10));

            // Pop and peek (should be None)
            assert_eq!(queue.pop(), Some(10));
            assert_eq!(queue.peek(), None);

            // Push multiple, peek first
            queue.push(20);
            queue.push(30);
            assert_eq!(queue.peek(), Some(&20));

            // Pop first, peek should show next
            assert_eq!(queue.pop(), Some(20));
            assert_eq!(queue.peek(), Some(&30));

            // Pop last, peek should be None
            assert_eq!(queue.pop(), Some(30));
            assert_eq!(queue.peek(), None);
        });
    }
}
