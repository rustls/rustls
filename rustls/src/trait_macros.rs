/// pub trait that includes Send & Sync - supports use with alloc::sync::Arc
#[cfg(not(feature = "withrcalias"))]
macro_rules! pub_api_trait {
    ($name:ident, $body:tt) => {
        pub trait $name: core::fmt::Debug + Send + Sync $body
    }
}

/// pub trait with no Send / Sync - supports use with alloc::rc::Rc
#[cfg(feature = "withrcalias")]
macro_rules! pub_api_trait {
    ($name:ident, $body:tt) => {
        pub trait $name: core::fmt::Debug $body
    }
}

/// internal pub(crate) trait that includes Send & Sync - supports use with alloc::sync::Arc
#[cfg(not(feature = "withrcalias"))]
macro_rules! internal_generic_state_trait {
    // XXX QUICK HACKY MACRO API WITH SEPARATE NAME & GENERIC TYPE PARAMETERS
    ($name:ident, $generic_type_parameter:ident, $body:tt) => {
        pub(crate) trait $name<$generic_type_parameter>: Send + Sync $body
    }
}

/// internal pub(crate) trait with no Send / Sync - supports use with alloc::rc::Rc
#[cfg(feature = "withrcalias")]
macro_rules! internal_generic_state_trait {
    // XXX QUICK HACKY MACRO API WITH SEPARATE NAME & GENERIC TYPE PARAMETERS
    ($name:ident, $generic_type_parameter:ident, $body:tt) => {
        pub(crate) trait $name<$generic_type_parameter> $body
    }
}
