#[cfg(not(feature = "withrcalias"))]
pub(crate) use alloc::sync::Arc;

#[cfg(feature = "withrcalias")]
pub(crate) use alloc::rc::Rc as Arc;
