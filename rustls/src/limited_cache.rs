use caches::Cache;
use core::hash::Hash;

pub(crate) trait CacheExt<K: Clone + Hash + Eq, V: Default> {
    fn get_or_insert_default_and_edit(&mut self, k: K, edit: impl FnOnce(&mut V));
}

impl<K: Clone + Hash + Eq, V: Default, C: Cache<K, V>> CacheExt<K, V> for C {
    fn get_or_insert_default_and_edit(&mut self, k: K, edit: impl FnOnce(&mut V)) {
        if self.contains(&k) {
            edit(self.get_mut(&k).unwrap());
        } else {
            let mut val = V::default();
            edit(&mut val);

            // TODO: there seems to have a bug on caches-rs where if the key was both recently or frequently removed, but the entry only reside on one place, making an option unwrap failed,
            // this is technically an optimization to take the evicted box out and try to put it back inline, but nonetheless failed to do so, we could workaround it
            // by fully evicting the key (this should be a no-op anyway)
            self.remove(&k);
            self.put(k, val);
        }
    }
}

#[cfg(test)]
mod test {
    use super::CacheExt;
    use caches::Cache;

    type Test = caches::AdaptiveCache<String, usize>;

    #[test]
    fn test_updates_existing_item() {
        let mut t = Test::new(3 - 1).unwrap();
        t.put("abc".into(), 1);
        t.put("abc".into(), 2);
        assert_eq!(t.get("abc"), Some(&2));
    }

    #[test]
    fn test_evicts_oldest_item() {
        let mut t = Test::new(3 - 1).unwrap();
        t.put("abc".into(), 1);
        t.put("def".into(), 2);
        t.put("ghi".into(), 3);

        assert_eq!(t.get("abc"), None);
        assert_eq!(t.get("def"), Some(&2));
        assert_eq!(t.get("ghi"), Some(&3));
    }

    #[test]
    fn test_evicts_second_oldest_item_if_first_removed() {
        let mut t = Test::new(3 - 1).unwrap();
        t.put("abc".into(), 1);
        t.put("def".into(), 2);

        assert_eq!(t.remove("abc"), Some(1));

        t.put("ghi".into(), 3);
        t.put("jkl".into(), 4);

        assert_eq!(t.get("abc"), None);
        assert_eq!(t.get("def"), None);
        assert_eq!(t.get("ghi"), Some(&3));
        assert_eq!(t.get("jkl"), Some(&4));
    }

    #[test]
    fn test_evicts_after_second_oldest_item_removed() {
        let mut t = Test::new(3 - 1).unwrap();
        t.put("abc".into(), 1);
        t.put("def".into(), 2);

        assert_eq!(t.remove("def"), Some(2));
        assert_eq!(t.get("abc"), Some(&1));

        t.put("ghi".into(), 3);
        t.put("jkl".into(), 4);

        assert_eq!(t.get("abc"), Some(&1));
        assert_eq!(t.get("def"), None);
        assert_eq!(t.get("ghi"), None);
        assert_eq!(t.get("jkl"), Some(&4));
    }

    #[test]
    fn test_removes_all_items() {
        let mut t = Test::new(3 - 1).unwrap();
        t.put("abc".into(), 1);
        t.put("def".into(), 2);

        assert_eq!(t.remove("def"), Some(2));
        assert_eq!(t.remove("abc"), Some(1));

        t.put("ghi".into(), 3);
        t.put("jkl".into(), 4);
        t.put("mno".into(), 5);

        assert_eq!(t.get("abc"), None);
        assert_eq!(t.get("def"), None);
        assert_eq!(t.get("ghi"), None);
        assert_eq!(t.get("jkl"), Some(&4));
        assert_eq!(t.get("mno"), Some(&5));
    }

    #[test]
    fn test_inserts_many_items() {
        let mut t = Test::new(3 - 1).unwrap();

        for _ in 0..10000 {
            t.put("abc".into(), 1);
            t.put("def".into(), 2);
            t.put("ghi".into(), 3);
        }
    }

    #[test]
    fn test_get_or_insert_default_and_edit_evicts_old_items_to_meet_capacity() {
        let mut t = Test::new(3 - 1).unwrap();

        t.get_or_insert_default_and_edit("abc".into(), |v| *v += 1);
        t.get_or_insert_default_and_edit("def".into(), |v| *v += 2);

        // evicts "abc"
        t.get_or_insert_default_and_edit("ghi".into(), |v| *v += 3);
        assert_eq!(t.get("abc"), None);

        // evicts "def"
        t.get_or_insert_default_and_edit("jkl".into(), |v| *v += 4);
        assert_eq!(t.get("def"), None);

        // evicts "ghi"
        t.get_or_insert_default_and_edit("abc".into(), |v| *v += 5);
        assert_eq!(t.get("ghi"), None);

        // evicts "jkl"
        t.get_or_insert_default_and_edit("def".into(), |v| *v += 6);

        assert_eq!(t.get("abc"), Some(&5));
        assert_eq!(t.get("def"), Some(&6));
        assert_eq!(t.get("ghi"), None);
        assert_eq!(t.get("jkl"), None);
    }

    #[test]
    fn test_get_or_insert_default_and_edit_edits_existing_item() {
        let mut t = Test::new(3 - 1).unwrap();

        t.get_or_insert_default_and_edit("abc".into(), |v| *v += 1);
        t.get_or_insert_default_and_edit("abc".into(), |v| *v += 2);
        t.get_or_insert_default_and_edit("abc".into(), |v| *v += 3);

        assert_eq!(t.get("abc"), Some(&6));
    }
}
