use crate::{Error, Result};

/// Longest org, app, channel, update or release id.
pub(crate) const MAX_ID: usize = 128;
/// Longest free-text field (notes, advisories).
pub(crate) const MAX_TEXT: usize = 16 * 1024;

/// Ids are 1..=128 ASCII letters, digits and `. - _ : / +`.
pub(crate) fn check_id(what: &'static str, id: &str) -> Result<()> {
    if id.is_empty() || id.len() > MAX_ID {
        return Err(Error::invalid(what, format!("length must be 1..={MAX_ID}")));
    }
    if !id.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_:/+".contains(&b)) {
        return Err(Error::invalid(what, "only ASCII letters, digits and . - _ : / + are allowed"));
    }
    Ok(())
}

pub(crate) fn check_text(what: &'static str, text: &str) -> Result<()> {
    if text.len() > MAX_TEXT {
        return Err(Error::invalid(what, format!("longer than {MAX_TEXT} bytes")));
    }
    Ok(())
}

pub(crate) fn check_unique<T: Ord + Clone>(what: &'static str, items: &[T]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for item in items {
        if !seen.insert(item.clone()) {
            return Err(Error::invalid(what, "duplicate entry"));
        }
    }
    Ok(())
}
