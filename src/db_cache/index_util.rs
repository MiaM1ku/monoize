use dashmap::DashMap;

pub(crate) fn remove_index_member(
    index: &DashMap<String, std::collections::HashSet<String>>,
    index_key: &str,
    cache_key: &str,
) {
    let remove_empty = if let Some(mut members) = index.get_mut(index_key) {
        members.remove(cache_key);
        members.is_empty()
    } else {
        false
    };
    if remove_empty {
        index.remove_if(index_key, |_, members| members.is_empty());
    }
}

