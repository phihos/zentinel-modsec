//! Variable system for ModSecurity.
//!
//! This module handles variable resolution and collection management.

mod collection;
mod json;
mod key_regex;
mod request;
mod resolver;
mod response;
mod tx;

pub use collection::{Collection, HashMapCollection, MutableCollection};
pub use key_regex::KeyRegex;
pub use request::RequestData;
pub use resolver::{ResolvedName, ResolvedValue, VariableResolver};
pub use response::ResponseData;
pub use tx::TxCollection;
