use crate::{Error, Result};
use serde::{Serialize, de::DeserializeOwned};

pub(crate) fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| Error::Encode(e.to_string()))?;
    Ok(out)
}

/// Decodes exactly one CBOR value; trailing bytes are refused.
pub(crate) fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value = ciborium::from_reader(&mut cursor).map_err(|e| Error::Decode(e.to_string()))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Error::Decode("trailing bytes after the value".into()));
    }
    Ok(value)
}
