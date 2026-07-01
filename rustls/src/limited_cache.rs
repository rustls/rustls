use alloc::collections::VecDeque;
use core::borrow::Borrow;
use core::hash::{BuildHasher, Hash};
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
    ghost_map: HashMap<u32, u64>,
    ghost_timer: u64,
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
            ghost_map: HashMap::with_capacity(ghost_capacity),
            ghost_timer: 0,
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

    /// A little difference from the original S3-FIFO `get` designed behavior
    /// we want the function to get value and modify it in place if it exists
    /// otherwise insert default and modify it in place
    pub(crate) fn get_or_insert_default_and_edit(&mut self, k: K, edit: impl FnOnce(&mut V)) {
        if let Some(value) = self.get_mut(&k) {
            edit(value);
            return;
        }

        let mut value = V::default();
        edit(&mut value);
        self.insert(k, value);
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

        let is_ghost_hit = self.is_ghost_hit(&k);
        if is_ghost_hit {
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
        if self.small.len() >= self.small_capacity {
            self.evict_small();
        }
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

    fn insert_ghost(&mut self, k: &K) {
        let fp = self.fingerprint(k);
        self.ghost_timer += 1;

        self.ghost_map
            .insert(fp, self.ghost_timer);
    }

    fn evict(&mut self) {
        if self.small.len() >= self.small_capacity {
            self.evict_small();
        } else {
            self.evict_main();
        }
    }

    fn evict_small(&mut self) {
        while let Some(k) = self.small.pop_front() {
            let Some(entry) = self.map.get(&k) else {
                continue;
            };

            if entry.state.current_frequency() > 1 {
                self.main.push_back(k);
                if self.main.len() > self.main_capacity {
                    self.evict_main();
                }
                return;
            } else {
                self.insert_ghost(&k);
                self.map.remove(&k);
                return;
            }
        }
    }

    fn evict_main(&mut self) {
        while let Some(k) = self.main.pop_front() {
            let entry = self.map.get(&k).unwrap();

            if entry.state.current_frequency() > 0 {
                entry.state.decrease_frequency();
                self.main.push_back(k);
            } else {
                self.map.remove(&k);
                return;
            }
        }
    }

    fn is_ghost_hit(&mut self, k: &K) -> bool {
        let fp = self.fingerprint(k);
        if let Some(&insertion_time) = self.ghost_map.get(&fp) {
            if self
                .ghost_timer
                .saturating_sub(insertion_time)
                < self.ghost_capacity as u64
            {
                self.ghost_map.remove(&fp);
                return true;
            } else {
                self.ghost_map.remove(&fp);
            }
        }
        false
    }

    fn fingerprint(&self, k: &K) -> u32 {
        let h = self.map.hasher().hash_one(k);
        (h ^ (h >> 32)) as u32
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
        assert!(!cache.is_ghost_hit(&k1), "k1 should not be in ghost");
        assert!(cache.map.contains_key(&k1), "k1 must still exist in map");
    }

    #[test]
    fn test_eviction_to_ghost() {
        let mut cache = TestCache::new(10);

        let k1 = String::from("key1");
        let k2 = String::from("key2");

        cache.insert(k1.clone(), 100);

        for i in 0..9 {
            cache.insert(format!("fill{}", i), i);
        }

        cache.insert(k2, 200);

        assert!(!cache.map.contains_key(&k1));
        assert!(cache.is_ghost_hit(&k1));
    }

    #[test]
    fn test_ghost_reinsertion_to_main() {
        let mut cache = TestCache::new(10);

        let k1 = String::from("key1");
        cache.insert(k1.clone(), 100);
        for i in 0..10 {
            cache.insert(format!("fill{}", i), i);
        }

        assert!(
            cache
                .ghost_map
                .contains_key(&cache.fingerprint(&k1)),
            "k1 should be in ghost"
        );

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
            cache.insert_ghost(k);
            cache.insert(k.clone(), i);
        }

        cache.get(&keys[0]);

        cache.insert_ghost(&keys[3]);
        cache.insert(keys[3].clone(), 3);

        assert!(cache.main.contains(&keys[0]));
        assert!(!cache.map.contains_key(&keys[1]));
    }

    #[test]
    fn test_frequency_saturation() {
        let mut cache = TestCache::new(10);
        let k = String::from("key");
        cache.insert(k.clone(), 0);

        for _ in 0..5 {
            cache.get(&k);
        }

        let entry = cache.map.get(&k).unwrap();
        assert_eq!(entry.state.current_frequency(), 3);
    }

    #[test]
    fn test_ghost_capacity_eviction() {
        let mut cache = TestCache::new(10);

        for i in 0..22 {
            cache.insert(format!("{}", i), i);
        }

        let k0 = String::from("0");
        assert!(!cache.is_ghost_hit(&k0));

        let k21 = String::from("21");
        assert!(cache.map.contains_key(&k21));
    }

    #[test]
    fn test_arc_interference() {
        let mut cache = TestCache::new(10);
        let k = String::from("key");
        cache.insert(k.clone(), 100);

        let entry_arc = cache.map.get(&k).unwrap().clone();

        cache.get_or_insert_default_and_edit(k.clone(), |v| *v = 200);

        assert_eq!(*cache.get(&k).unwrap(), 200);
        assert_eq!(entry_arc.value, 100);
    }

    #[test]
    fn test_main_saturation() {
        let mut cache = TestCache::new(10);

        for i in 0..10 {
            let k = format!("{}", i);
            cache.insert(k.clone(), i);
            cache.get(&k);
            cache.get(&k);
        }

        cache.insert(String::from("overflow"), 999);

        assert_eq!(cache.main.len(), 9);
        assert!(!cache.map.contains_key("0"));
    }

    #[test]
    fn test_remove_missing() {
        let mut cache = TestCache::new(10);
        assert_eq!(cache.remove("missing"), None);
    }

    #[test]
    fn test_get_missing() {
        let cache = TestCache::new(10);
        assert_eq!(cache.get("missing"), None);
    }

    #[test]
    fn test_get_mut_missing() {
        let mut cache = TestCache::new(10);
        assert_eq!(cache.get_mut("missing"), None);
    }

    #[test]
    fn test_zombie_in_small() {
        let mut cache = TestCache::new(2);

        cache.insert(String::from("A"), 1);
        cache.remove("A");

        cache.insert(String::from("B"), 2);
        cache.insert(String::from("C"), 3);

        assert!(!cache.map.contains_key("A"));
        assert!(cache.map.contains_key("C"));
    }

    #[test]
    fn test_zombie_in_main() {
        let mut cache = TestCache::new(10);
        let k = String::from("A");
        cache.insert(k.clone(), 1);
        cache.get(&k);
        cache.get(&k);

        for i in 0..10 {
            cache.insert(format!("fill{}", i), i);
        }

        assert!(cache.main.contains(&k));

        cache.remove(&k);

        for i in 0..20 {
            let k2 = format!("m{}", i);
            cache.insert(k2.clone(), i);
            cache.get(&k2);
        }
        assert!(!cache.map.contains_key("A"));
    }

    #[test]
    fn test_get_or_insert_eviction() {
        let mut cache = TestCache::new(2);
        cache.insert(String::from("A"), 1);
        cache.insert(String::from("B"), 2);

        cache.get_or_insert_default_and_edit(String::from("C"), |v| *v = 3);

        assert!(cache.map.contains_key("C"));
        assert!(cache.map.len() <= 2);
    }

    // ? Do we actually need Debug impl and tests for it?
    #[test]
    fn test_debug_impls() {
        let mut cache = TestCache::new(10);
        cache.insert(String::from("A"), 1);
        let output = format!("{:?}", cache);
        assert!(output.contains("LimitedCache"));
        assert!(output.contains("A"));

        assert!(output.contains("CacheEntry"));
        assert!(output.contains("EntryState"));
    }

    #[test]
    fn test_get_or_insert_simple_update() {
        let mut cache = TestCache::new(10);
        cache.insert(String::from("key"), 100);

        cache.get_or_insert_default_and_edit(String::from("key"), |v| *v = 200);

        assert_eq!(*cache.get("key").unwrap(), 200);
    }

    #[test]
    fn test_entry_state_logic() {
        let state = EntryState {
            frequency: AtomicU8::new(0),
        };

        state.decrease_frequency();
        assert_eq!(state.current_frequency(), 0);

        state.increase_frequency_max_3();
        assert_eq!(state.current_frequency(), 1);

        state.increase_frequency_max_3();
        state.increase_frequency_max_3();
        state.increase_frequency_max_3();
        assert_eq!(state.current_frequency(), 3);

        state.decrease_frequency();
        assert_eq!(state.current_frequency(), 2);
    }

    #[test]
    fn test_minimal_capacity() {
        let mut cache = TestCache::new(1);

        cache.insert(String::from("A"), 1);
        cache.get("A");

        cache.insert(String::from("B"), 2);

        assert!(cache.map.contains_key("B"));
        assert!(!cache.map.contains_key("A"));
    }

    #[test]
    fn test_decrease_frequency_saturation() {
        let state = EntryState {
            frequency: AtomicU8::new(0),
        };
        state.decrease_frequency();
        assert_eq!(state.current_frequency(), 0);
    }
}
