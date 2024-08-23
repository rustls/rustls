#[cfg(not(feature = "withrcalias"))]
pub use alloc::sync::Arc;

#[cfg(feature = "withrcalias")]
pub use alloc::rc::Rc as Arc;
