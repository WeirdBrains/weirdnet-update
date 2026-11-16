//! The announcement stream protocol, [`PROTOCOL`], between devices, publishers and carriers.
//!
//! The first frame decides the stream's kind:
//!
//! - [`ToCarrier::Subscribe`]: a device (topics) or a following carrier (`all`). The carrier
//!   answers [`FromCarrier::Subscribed`], sends what it holds that matches, then each new
//!   matching announcement and root rotation as it arrives, with keepalives in between.
//! - [`ToCarrier::Publish`]: a publisher (or a carrier passing one on) offers announcements
//!   and root rotations; the carrier answers [`FromCarrier::Published`] for each.
//!
//! Frames are CBOR, each after a 4-byte big-endian length, at most [`MAX_FRAME`] bytes.
//! Transport-neutral: any `futures` `AsyncRead + AsyncWrite`, such as a `weirdnet-net`
//! stream.

use super::{Offered, Topic};
use crate::envelope::Signed;
use crate::{Error, Result, cbor};
use futures_util::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde::{Deserialize, Serialize};

/// The stream protocol id.
pub const PROTOCOL: &str = "/weirdnet/updates/1";
/// The largest frame.
pub const MAX_FRAME: usize = 64 * 1024;
/// Most topics in one subscription.
pub const MAX_TOPICS: usize = 64;
/// Most envelopes in one publish frame.
pub const MAX_PUBLISH: usize = 32;

/// To a carrier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToCarrier {
    /// Hear about these topics (devices), or everything the carrier holds (`all`, for
    /// carriers following each other).
    Subscribe {
        /// At most [`MAX_TOPICS`].
        topics: Vec<Topic>,
        /// Everything.
        #[serde(default)]
        all: bool,
    },
    /// Announcements and root rotations to carry.
    Publish {
        /// At most [`MAX_PUBLISH`].
        envelopes: Vec<Signed>,
    },
}

/// From a carrier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FromCarrier {
    /// The subscription is in place.
    Subscribed {
        /// Keepalives come at least this often.
        keepalive_s: u32,
    },
    /// An announcement or a root rotation.
    Envelope(Signed),
    /// Nothing new.
    Keepalive,
    /// One answer per published envelope, in order: what happened, or why it was refused.
    Published(Vec<std::result::Result<Offered, String>>),
    /// The request was refused.
    Error(String),
}

/// Writes one frame.
pub async fn write<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<()> {
    let body = cbor::to_vec(msg)?;
    if body.len() > MAX_FRAME {
        return Err(Error::invalid("frame", "too large"));
    }
    let mut b = (body.len() as u32).to_be_bytes().to_vec();
    b.extend(body);
    w.write_all(&b).await.map_err(io)?;
    w.flush().await.map_err(io)
}

/// Reads one frame; `None` at a clean end of stream.
pub async fn read<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(r: &mut R) -> Result<Option<T>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(io(e)),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(Error::Decode("bad frame length".into()));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await.map_err(io)?;
    cbor::from_slice(&body).map(Some)
}

fn io(e: std::io::Error) -> Error {
    Error::Decode(format!("stream: {e}"))
}

/// A device's (or a following carrier's) subscription.
pub struct Subscription<S> {
    io: S,
    /// The carrier's keepalive interval.
    pub keepalive_s: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Subscription<S> {
    /// Subscribes on a fresh stream.
    pub async fn start(mut io: S, topics: Vec<Topic>, all: bool) -> Result<Self> {
        if topics.len() > MAX_TOPICS || (topics.is_empty() && !all) {
            return Err(Error::invalid("subscription", format!("1 to {MAX_TOPICS} topics, or all")));
        }
        write(&mut io, &ToCarrier::Subscribe { topics, all }).await?;
        match read(&mut io).await? {
            Some(FromCarrier::Subscribed { keepalive_s }) => Ok(Self { io, keepalive_s }),
            Some(FromCarrier::Error(e)) => Err(Error::invalid("subscription", e)),
            _ => Err(Error::Decode("unexpected answer to subscribe".into())),
        }
    }

    /// The next envelope, skipping keepalives; `None` when the carrier closed the stream.
    /// Verify it ([`crate::Client::verify_announcement`], [`crate::Client::update_root`])
    /// before acting on it.
    pub async fn next(&mut self) -> Result<Option<Signed>> {
        loop {
            match read(&mut self.io).await? {
                None => return Ok(None),
                Some(FromCarrier::Envelope(e)) => return Ok(Some(e)),
                Some(FromCarrier::Keepalive) => continue,
                Some(FromCarrier::Error(e)) => return Err(Error::invalid("carrier", e)),
                Some(_) => return Err(Error::Decode("unexpected frame".into())),
            }
        }
    }
}

/// Publishes envelopes to a carrier over a fresh stream.
pub async fn publish<S: AsyncRead + AsyncWrite + Unpin>(mut io: S, envelopes: Vec<Signed>) -> Result<Vec<std::result::Result<Offered, String>>> {
    if envelopes.is_empty() || envelopes.len() > MAX_PUBLISH {
        return Err(Error::invalid("publish", format!("1 to {MAX_PUBLISH} envelopes")));
    }
    write(&mut io, &ToCarrier::Publish { envelopes }).await?;
    let r = read(&mut io).await?;
    let _ = io.close().await;
    match r {
        Some(FromCarrier::Published(v)) => Ok(v),
        Some(FromCarrier::Error(e)) => Err(Error::invalid("carrier", e)),
        _ => Err(Error::Decode("unexpected answer to publish".into())),
    }
}
