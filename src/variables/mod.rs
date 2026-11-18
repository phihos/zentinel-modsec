//! Variable system for ModSecurity.
//!
//! This module handles variable resolution and collection management.

mod collection;
mod json;
mod request;
mod resolver;
mod response;
mod tx;
mod value;

pub use collection::{ByteCollection, Collection, HashMapCollection, MutableCollection};
pub use request::RequestData;
pub(crate) use resolver::cached_collection_regex;
pub use resolver::VariableResolver;
pub use response::ResponseData;
pub use tx::TxCollection;
pub use value::ByteValue;
