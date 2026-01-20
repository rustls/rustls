use alloc::collections::VecDeque;
use core::borrow::Borrow;
use core::fmt::Debug;
use core::hash::Hash;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::hash_map::{Entry, HashMap};
use crate::sync::Arc;

const BIT_ACCESSED: u8 = 0b01;

struct CacheEntry<V> {
    value: V,
    state: AtomicU8,
}

pub(crate) struct S3FifoShard<K: Eq + Hash + Clone + Debug, V> {
    map: HashMap<K, Arc<CacheEntry<V>>>,
    small: VecDeque<K>,
    main: VecDeque<K>,
    ghost: VecDeque<K>,
    small_capacity: usize,
    main_capacity: usize,
    ghost_capacity: usize,
}

impl<K, V> S3FifoShard<K, V>
where
    K: Eq + Hash + Clone + Debug,
    V: Default,
{
    pub(crate) fn new(capacity: usize) -> Self {
        let small_capacity = capacity / 10;
        let main_capacity = capacity - small_capacity;
        Self {
            map: HashMap::with_capacity(capacity),
            small: VecDeque::with_capacity(small_capacity),
            main: VecDeque::with_capacity(main_capacity),
            ghost: VecDeque::with_capacity(main_capacity),
            small_capacity,
            main_capacity,
            ghost_capacity: main_capacity,
        }
    }

    #[inline]
    pub(crate) fn get<Q: Hash + Eq + ?Sized>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        let entry = self.map.get(k)?;
        entry
            .state
            .fetch_or(BIT_ACCESSED, Ordering::Relaxed);
        Some(&entry.value)
    }

    #[inline]
    pub(crate) fn insert(&mut self, k: K, v: V) {
        match self.map.entry(k.clone()) {
            Entry::Occupied(mut occupied_entry) => {
                let entry = Arc::new(CacheEntry {
                    value: v,
                    state: AtomicU8::new(BIT_ACCESSED),
                });

                occupied_entry.insert(entry);
            }
            Entry::Vacant(occupied_entry) => {
                let entry = Arc::new(CacheEntry {
                    value: v,
                    state: AtomicU8::new(0),
                });

                occupied_entry.insert(entry.clone());

                if let Some(pos) = self.ghost.iter().position(|x| x == &k) {
                    self.ghost.remove(pos);
                    self.insert_main(k.clone(), entry);
                } else {
                    self.insert_small(k, entry);
                }
            }
        }
    }

    #[inline]
    pub(crate) fn remove<Q: Hash + Eq + ?Sized>(&mut self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
    {
        let entry = self.map.remove(k)?;
        Some(
            Arc::try_unwrap(entry)
                .ok()
                .unwrap()
                .value,
        )
    }

    #[inline]
    fn insert_small(&mut self, k: K, entry: Arc<CacheEntry<V>>) {
        if self.small.len() >= self.small_capacity {
            self.evict_small();
        }
        self.small.push_back(k.clone());
        self.map.insert(k, entry);
    }

    #[inline]
    fn insert_main(&mut self, k: K, entry: Arc<CacheEntry<V>>) {
        if self.main.len() >= self.main_capacity {
            self.evict_main();
        }
        self.main.push_back(k.clone());
        self.map.insert(k, entry);
    }

    #[inline]
    fn insert_ghost(&mut self, k: K) {
        if self.ghost.len() >= self.ghost_capacity {
            self.ghost.pop_front();
        }
        self.ghost.push_back(k);
    }

    #[inline]
    fn evict_small(&mut self) {
        let Some(k) = self.small.pop_front() else {
            return;
        };
        let Some(entry) = self.map.get(&k) else {
            return;
        };

        if entry.state.load(Ordering::Relaxed) & BIT_ACCESSED != 0 {
            entry
                .state
                .fetch_and(!BIT_ACCESSED, Ordering::Relaxed);
            self.insert_main(k, entry.clone());
        } else {
            self.insert_ghost(k.clone());
            self.map.remove(&k);
        }
    }

    #[inline]
    fn evict_main(&mut self) {
        if self.main.is_empty() {
            return;
        }

        let max_iterations = self.main.len();
        for _ in 0..max_iterations {
            let Some(k) = self.main.pop_front() else {
                break;
            };
            let Some(entry) = self.map.get(&k) else {
                continue;
            };

            if entry.state.load(Ordering::Relaxed) & BIT_ACCESSED != 0 {
                entry
                    .state
                    .fetch_and(!BIT_ACCESSED, Ordering::Relaxed);
                self.main.push_back(k);
            } else {
                self.map.remove(&k);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use super::*;

    type TestCache = S3FifoShard<String, usize>;

    #[test]
    fn test_s3_fifo_insert_and_get() {
        let mut cache = TestCache::new(10);
        cache.insert("key1".into(), 100);

        let value = cache
            .get("key1")
            .expect("Item should exist");
        assert_eq!(*value, 100);

        let entry = cache.map.get("key1").unwrap();
        assert_eq!(
            entry.state.load(Ordering::Relaxed) & BIT_ACCESSED,
            BIT_ACCESSED
        );
    }

    #[test]
    fn test_small_to_ghost_eviction() {
        let mut cache = TestCache::new(10);
        let k1 = String::from("key1");
        let k2 = String::from("key2");

        cache.insert(k1.clone(), 1);
        cache.insert(k2, 2);

        assert!(!cache.map.contains_key(&k1));
        assert!(cache.ghost.contains(&k1));
    }

    #[test]
    fn test_small_to_main_promotion() {
        let mut cache = TestCache::new(10);
        let k1 = String::from("key1");
        let k2 = String::from("key2");

        cache.insert(k1.clone(), 1);
        cache.get(&k1);

        cache.insert(k2, 2);

        assert!(cache.map.contains_key(&k1));
        assert!(cache.main.contains(&k1));

        let entry = cache.map.get(&k1).unwrap();
        assert_eq!(entry.state.load(Ordering::Relaxed) & BIT_ACCESSED, 0);
    }

    #[test]
    fn test_main_second_chance_eviction() {
        let mut cache = TestCache::new(10);
        let k1 = String::from("key1");

        cache.insert_ghost(k1.clone());
        cache.insert(k1.clone(), 1);

        cache.get(&k1);

        cache.evict_main();

        assert!(cache.map.contains_key(&k1));
        let entry = cache.map.get(&k1).unwrap();
        assert_eq!(entry.state.load(Ordering::Relaxed) & BIT_ACCESSED, 0);
    }

    #[test]
    fn test_ghost_track_and_reuse() {
        let mut cache = TestCache::new(10);
        let k1 = String::from("key1");
        let k2 = String::from("key2");

        cache.insert(k1.clone(), 1);
        cache.insert(k2, 2);

        assert!(!cache.map.contains_key(&k1));
        assert!(cache.ghost.contains(&k1));

        cache.insert(k1.clone(), 1);
        assert!(cache.map.contains_key(&k1));
        assert!(cache.main.contains(&k1));
        assert!(!cache.ghost.contains(&k1));
    }

    #[test]
    fn test_remove_functional() {
        let mut cache = TestCache::new(10);
        cache.insert("key1".into(), 42);

        let val = cache.remove("key1");
        assert_eq!(val, Some(42));
        assert!(!cache.map.contains_key("key1"));
    }
}
