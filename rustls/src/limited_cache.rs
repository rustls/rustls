use std::borrow::Borrow;
use std::collections::hash_map::{DefaultHasher, Entry};
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

/// A HashMap-alike, which never gets larger than a specified
/// capacity, and evicts the oldest insertion to maintain this.
///
/// The requested capacity may be rounded up by the underlying
/// collections.  This implementation uses all the allocated
/// storage.
///
/// This is inefficient: it stores the hash of the keys twice.
pub(crate) struct LimitedCache<K: Hash + Eq, V> {
    map: HashMap<u64, V>,

    // first item is the oldest key
    oldest: VecDeque<u64>,
    phantom: PhantomData<K>,
}

impl<K, V> LimitedCache<K, V>
where
    K: Hash + Eq,
{
    /// Create a new LimitedCache with the given rough capacity.
    pub(crate) fn new(capacity_order_of_magnitude: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity_order_of_magnitude),
            oldest: VecDeque::with_capacity(capacity_order_of_magnitude),
            phantom: PhantomData,
        }
    }

    pub(crate) fn get_or_insert_default_and_edit<Q: ?Sized>(
        &mut self,
        k: &Q,
        edit: impl FnOnce(&mut V),
    ) where
        K: Borrow<Q>,
        Q: Hash + Eq,
        V: Default,
    {
        let k_hash = make_hash(k);

        let inserted_new_item = match self.map.entry(k_hash) {
            Entry::Occupied(value) => {
                edit(value.into_mut());
                false
            }
            entry @ Entry::Vacant(_) => {
                self.oldest.push_back(k_hash);
                edit(entry.or_insert_with(V::default));
                true
            }
        };

        // ensure next insertion does not require a realloc
        if inserted_new_item && self.oldest.capacity() == self.oldest.len() {
            if let Some(oldest_key) = self.oldest.pop_front() {
                self.map.remove(&oldest_key);
            }
        }
    }

    pub(crate) fn insert<Q: ?Sized>(&mut self, k: &Q, v: V)
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        let k_hash = make_hash(k);

        let inserted_new_item = match self.map.entry(k_hash) {
            Entry::Occupied(mut old) => {
                // nb. does not freshen entry in `oldest`
                old.insert(v);
                false
            }

            entry @ Entry::Vacant(_) => {
                self.oldest.push_back(k_hash);
                entry.or_insert(v);
                true
            }
        };

        // ensure next insertion does not require a realloc
        if inserted_new_item && self.oldest.capacity() == self.oldest.len() {
            if let Some(oldest_key) = self.oldest.pop_front() {
                self.map.remove(&oldest_key);
            }
        }
    }

    pub(crate) fn get<Q: ?Sized>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        let k_hash = make_hash(&k);
        self.map.get(&k_hash)
    }

    pub(crate) fn get_mut<Q: ?Sized>(&mut self, k: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        let k_hash = make_hash(&k);
        self.map.get_mut(&k_hash)
    }

    pub(crate) fn remove<Q: ?Sized>(&mut self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        let k_hash = make_hash(&k);

        self.map.remove(&k_hash).map(|value| {
            // O(N) search, followed by O(N) removal
            if let Some(index) = self
                .oldest
                .iter()
                .position(|item| *item == k_hash)
            {
                self.oldest.remove(index);
            }

            value
        })
    }
}

fn make_hash<K: ?Sized>(key: &K) -> u64
where
    K: Hash + Eq,
{
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod test {
    type Test = super::LimitedCache<String, usize>;

    #[test]
    fn test_updates_existing_item() {
        let mut t = Test::new(3);
        t.insert("abc", 1);
        t.insert("abc", 2);
        assert_eq!(t.get("abc"), Some(&2));
    }

    #[test]
    fn test_evicts_oldest_item() {
        let mut t = Test::new(3);
        t.insert("abc", 1);
        t.insert("def", 2);
        t.insert("ghi", 3);

        assert_eq!(t.get("abc"), None);
        assert_eq!(t.get("def"), Some(&2));
        assert_eq!(t.get("ghi"), Some(&3));
    }

    #[test]
    fn test_evicts_second_oldest_item_if_first_removed() {
        let mut t = Test::new(3);
        t.insert("abc", 1);
        t.insert("def", 2);

        assert_eq!(t.remove("abc"), Some(1));

        t.insert("ghi", 3);
        t.insert("jkl", 4);

        assert_eq!(t.get("abc"), None);
        assert_eq!(t.get("def"), None);
        assert_eq!(t.get("ghi"), Some(&3));
        assert_eq!(t.get("jkl"), Some(&4));
    }

    #[test]
    fn test_evicts_after_second_oldest_item_removed() {
        let mut t = Test::new(3);
        t.insert("abc", 1);
        t.insert("def", 2);

        assert_eq!(t.remove("def"), Some(2));
        assert_eq!(t.get("abc"), Some(&1));

        t.insert("ghi", 3);
        t.insert("jkl", 4);

        assert_eq!(t.get("abc"), None);
        assert_eq!(t.get("def"), None);
        assert_eq!(t.get("ghi"), Some(&3));
        assert_eq!(t.get("jkl"), Some(&4));
    }

    #[test]
    fn test_removes_all_items() {
        let mut t = Test::new(3);
        t.insert("abc", 1);
        t.insert("def", 2);

        assert_eq!(t.remove("def"), Some(2));
        assert_eq!(t.remove("abc"), Some(1));

        t.insert("ghi", 3);
        t.insert("jkl", 4);
        t.insert("mno", 5);

        assert_eq!(t.get("abc"), None);
        assert_eq!(t.get("def"), None);
        assert_eq!(t.get("ghi"), None);
        assert_eq!(t.get("jkl"), Some(&4));
        assert_eq!(t.get("mno"), Some(&5));
    }

    #[test]
    fn test_inserts_many_items() {
        let mut t = Test::new(3);

        for _ in 0..10000 {
            t.insert("abc", 1);
            t.insert("def", 2);
            t.insert("ghi", 3);
        }
    }

    #[test]
    fn test_get_or_insert_default_and_edit_evicts_old_items_to_meet_capacity() {
        let mut t = Test::new(3);

        t.get_or_insert_default_and_edit("abc", |v| *v += 1);
        t.get_or_insert_default_and_edit("def", |v| *v += 2);

        // evicts "abc"
        t.get_or_insert_default_and_edit("ghi", |v| *v += 3);
        assert_eq!(t.get("abc"), None);

        // evicts "def"
        t.get_or_insert_default_and_edit("jkl", |v| *v += 4);
        assert_eq!(t.get("def"), None);

        // evicts "ghi"
        t.get_or_insert_default_and_edit("abc", |v| *v += 5);
        assert_eq!(t.get("ghi"), None);

        // evicts "jkl"
        t.get_or_insert_default_and_edit("def", |v| *v += 6);

        assert_eq!(t.get("abc"), Some(&5));
        assert_eq!(t.get("def"), Some(&6));
        assert_eq!(t.get("ghi"), None);
        assert_eq!(t.get("jkl"), None);
    }

    #[test]
    fn test_get_or_insert_default_and_edit_edits_existing_item() {
        let mut t = Test::new(3);

        t.get_or_insert_default_and_edit("abc", |v| *v += 1);
        t.get_or_insert_default_and_edit("abc", |v| *v += 2);
        t.get_or_insert_default_and_edit("abc", |v| *v += 3);

        assert_eq!(t.get("abc"), Some(&6));
    }
}
