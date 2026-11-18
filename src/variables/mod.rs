//! Variable system for ModSecurity.
//!
//! This module handles variable resolution and collection management.

mod collection;
mod json;
mod multipart;
mod request;
mod resolver;
mod response;
mod selectors;
mod tx;
mod value;
mod xml;
mod xml_entities;

pub use collection::{ByteCollection, Collection, HashMapCollection, MutableCollection};
pub use request::RequestData;
pub use resolver::VariableResolver;
pub use response::ResponseData;
pub use tx::TxCollection;
pub use value::ByteValue;

pub(crate) use collection::folded_key;
pub(crate) use selectors::{compile_selector, regex_exclusion, SelectorPrograms};
