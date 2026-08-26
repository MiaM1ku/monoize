//! UserStore persistence and auth helpers.
//!
//! Split by domain so each file stays under the ~1k-line maintainability bound.

mod helpers;
mod lifecycle;
mod accounts;
mod api_key_codec;
mod api_keys_read;
mod api_keys_write;
mod billing;

#[cfg(test)]
mod tests;

pub(crate) use helpers::{
    MAX_GROUP_IDS, decode_required_bool, parse_group_ids_json, serialize_group_ids_json,
};
