use alloc::collections::VecDeque;
use core::borrow::Borrow;
use core::hash::Hash;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::hash_map::HashMap;
use crate::sync::Arc;

#[derive(Debug)]
struct CacheEntry<V> {
    value: V,
    state: EntryState,
}

#[derive(Debug)]
struct EntryState {
    frequency: AtomicU8,
}

impl EntryState {
    fn current_frequency(&self) -> u8 {
        self.frequency.load(Ordering::Relaxed)
    }

    fn increase_frequency_max_3(&self) {
        let _ = self
            .frequency
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |f| {
                if f < 3 { Some(f + 1) } else { None }
            });
    }

    fn decrease_frequency(&self) {
        let _ = self
            .frequency
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |f| {
                Some(f.saturating_sub(1))
            });
    }
}

#[derive(Debug)]
pub(crate) struct LimitedCache<K: Clone + Hash + Eq, V> {
    map: HashMap<K, Arc<CacheEntry<V>>>,
    small: VecDeque<K>,
    main: VecDeque<K>,
    // TODO: migrate ghost to a HashSet for O(1) removes
    ghost: VecDeque<K>,
    small_capacity: usize,
    main_capacity: usize,
    ghost_capacity: usize,
    max_capacity: usize,
}

impl<K, V> LimitedCache<K, V>
where
    K: Eq + Hash + Clone + core::fmt::Debug,
    V: Default,
{
    pub(crate) fn new(capacity: usize) -> Self {
        let small_capacity = (capacity / 10).max(1);
        let main_capacity = capacity - small_capacity;
        let ghost_capacity = capacity;
        Self {
            map: HashMap::with_capacity(capacity),
            small: VecDeque::with_capacity(small_capacity),
            main: VecDeque::with_capacity(main_capacity),
            ghost: VecDeque::with_capacity(ghost_capacity),
            small_capacity,
            main_capacity,
            ghost_capacity,
            max_capacity: capacity,
        }
    }

    pub(crate) fn get<Q: Hash + Eq + ?Sized>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        let entry = self.map.get(k)?;
        entry.state.increase_frequency_max_3();
        Some(&entry.value)
    }

    pub(crate) fn get_mut<Q: Hash + Eq + ?Sized>(&mut self, k: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
    {
        let entry = self.map.get_mut(k)?;
        entry.state.increase_frequency_max_3();
        Arc::get_mut(entry).map(|e| &mut e.value)
    }

    pub(crate) fn get_or_insert_default_and_edit(&mut self, k: K, edit: impl FnOnce(&mut V)) {
        if let Some(entry) = self.map.get_mut(&k) {
            entry.state.increase_frequency_max_3();
            if let Some(v) = Arc::get_mut(entry) {
                edit(&mut v.value);
                return;
            }
        }

        while self.map.len() >= self.max_capacity {
            self.evict();
        }

        let mut entry_val = V::default();

        edit(&mut entry_val);

        let entry = Arc::new(CacheEntry {
            value: entry_val,
            state: EntryState {
                frequency: AtomicU8::new(0),
            },
        });

        if self.ghost.iter().any(|x| x == &k) {
            self.insert_main(k, entry);
        } else {
            self.insert_small(k, entry);
        }
    }

    pub(crate) fn insert(&mut self, k: K, v: V) {
        while self.map.len() >= self.max_capacity {
            self.evict();
        }

        let entry = Arc::new(CacheEntry {
            value: v,
            state: EntryState {
                frequency: AtomicU8::new(0),
            },
        });

        if self.ghost.iter().any(|x| x == &k) {
            self.insert_main(k, entry);
        } else {
            self.insert_small(k, entry);
        }
    }

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

    fn insert_small(&mut self, k: K, entry: Arc<CacheEntry<V>>) {
        // if self.small.len() >= self.small_capacity {
        //     self.evict_small();
        // }
        self.small.push_back(k.clone());
        self.map.insert(k, entry);
    }

    fn insert_main(&mut self, k: K, entry: Arc<CacheEntry<V>>) {
        // if self.main.len() >= self.main_capacity {
        //     self.evict_main();
        // }
        self.main.push_back(k.clone());
        self.map.insert(k, entry);
    }

    fn insert_ghost(&mut self, k: K) {
        if self.ghost.len() >= self.ghost_capacity {
            self.ghost.pop_front();
        }
        self.ghost.push_back(k);
    }

    fn evict(&mut self) {
        if self.small.len() >= self.small_capacity {
            self.evict_small();
        } else {
            self.evict_main();
        }
    }

    fn evict_small(&mut self) {
        let mut evicted = false;
        while !evicted && !self.small.is_empty() {
            let Some(k) = self.small.pop_front() else {
                break;
            };
            let Some(entry) = self.map.get(&k) else {
                continue;
            };

            if entry.state.current_frequency() > 1 {
                self.insert_main(k, entry.clone());
                if self.main.len() >= self.main_capacity {
                    self.evict_main();
                }
            } else {
                self.insert_ghost(k.clone());
                self.map.remove(&k);
                evicted = true;
            }
        }
    }

    fn evict_main(&mut self) {
        let mut evicted = false;
        while !evicted && !self.main.is_empty() {
            let Some(k) = self.main.pop_front() else {
                break;
            };

            let Some(entry) = self.map.get(&k) else {
                continue;
            };

            if entry.state.current_frequency() > 0 {
                entry.state.decrease_frequency();
                self.main.push_back(k);
            } else {
                self.map.remove(&k);
                evicted = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use std::format;
    use std::vec::Vec;

    use super::*;

    type TestCache = LimitedCache<String, usize>;

    #[test]
    fn test_new_capacity() {
        let cache = TestCache::new(10);
        assert_eq!(cache.small_capacity, 1);
        assert_eq!(cache.main_capacity, 9);
        assert_eq!(cache.ghost_capacity, 10);
    }

    #[test]
    fn test_promotion_small_to_main() {
        let mut cache = TestCache::new(10);

        let k1 = String::from("key1");

        cache.insert(k1.clone(), 100);

        cache.get(&k1);
        cache.get(&k1);

        for i in 0..9 {
            cache.insert(format!("fill{}", i), i);
        }

        cache.insert(String::from("trigger"), 999);

        assert!(
            cache.main.contains(&k1),
            "k1 should be promoted to main due to freq > 1"
        );
        assert!(!cache.ghost.contains(&k1), "k1 should not be in ghost");
        assert!(cache.map.contains_key(&k1), "k1 must still exist in map");
    }

    #[test]
    fn test_eviction_to_ghost() {
        let mut cache = TestCache::new(10);

        let k1 = String::from("key1");
        let k2 = String::from("key2");

        cache.insert(k1.clone(), 100);
        cache.get(&k1);

        for i in 0..9 {
            cache.insert(format!("fill{}", i), i);
        }

        cache.insert(k2, 200);

        assert!(!cache.map.contains_key(&k1));
        assert!(cache.ghost.contains(&k1));
    }

    #[test]
    fn test_ghost_reinsertion_to_main() {
        let mut cache = TestCache::new(10);

        let k1 = String::from("key1");
        cache.insert(k1.clone(), 100);
        for i in 0..10 {
            cache.insert(format!("fill{}", i), i);
        }

        assert!(cache.ghost.contains(&k1), "k1 should be in ghost");

        cache.insert(k1.clone(), 300);

        assert!(cache.main.contains(&k1));
        assert!(!cache.small.contains(&k1));
    }

    #[test]
    fn test_main_recirculation() {
        let mut cache = TestCache::new(3);

        let keys: Vec<String> = (0..4)
            .map(|i| format!("{}", i))
            .collect();

        for (i, k) in keys.iter().take(3).enumerate() {
            cache.insert_ghost(k.clone());
            cache.insert(k.clone(), i);
        }

        cache.get(&keys[0]);

        cache.insert_ghost(keys[3].clone());
        cache.insert(keys[3].clone(), 3);

        assert!(cache.main.contains(&keys[0]));
        assert!(!cache.map.contains_key(&keys[1]));
    }
}
