// NOTE: This `atomic_sync` module is intended to make it easier for a fork to
// use another implementation of `Arc` such as `portable_atomic_util::Arc`,
// which can help support build targets with no atomic pointer.
// This module also makes it really easy for CI to over-write this import
// for build & unit testing with `portable_atomic_util::Arc`.

pub(crate) use alloc::sync::Arc;
