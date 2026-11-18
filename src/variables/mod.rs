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

pub(crate) use collection::folded_key;
pub use collection::{ByteCollection, Collection, HashMapCollection, MutableCollection};
pub use request::RequestData;
pub(crate) use resolver::qualified_name;
pub use resolver::VariableResolver;
pub use response::ResponseData;
pub(crate) use selectors::{
    compile_selector, count_name, regex_exclusion, MemberSelector, SelectorPrograms,
    TargetSelection,
};
pub use tx::TxCollection;
pub use value::ByteValue;
