//! Cawala wire protocol.
//!
//! Postcard-serialized messages over a `u32` LE length-prefixed framing,
//! implemented over tokio `AsyncRead`/`AsyncWrite`. This crate must stay
//! wasm-safe: it is compiled for `wasm32-unknown-unknown` as a dependency of
//! the browser client, so tokio is used with `default-features = false` and
//! only the `io-util` feature.
//!
//! Also carries the octal hierarchical address type [`OctAddr`] (and the
//! topology's slot bound [`MAX_SLOT`]), which is pure `std` + `serde` and
//! therefore wasm-safe.

use std::io;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod addr;

pub use addr::{MAX_SLOT, OctAddr, ParseOctAddrError};

/// ALPN negotiated on every cawala/ping/0 connection.
pub const ALPN: &[u8] = b"cawala/ping/0";

/// Maximum accepted frame payload in bytes. Guards against unbounded
/// allocations from a misbehaving or malicious peer.
pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// A cawala ping/pong wire message.
#[derive(Debug, Serialize, Deserialize)]
pub enum PingPong {
    Ping { payload: Vec<u8> },
    Pong { seq: u64, payload: Vec<u8> },
}

/// Write one length-prefixed postcard frame to `w`.
///
/// Frame layout: `u32` LE byte-length followed by the postcard-encoded
/// value bytes. Generic over any [`Serialize`] type so higher-level crates
/// (e.g. the messaging envelope) can reuse the same wire framing without
/// going through [`PingPong`].
pub async fn write_framed<T, W>(w: &mut W, value: &T) -> io::Result<()>
where
    T: Serialize + ?Sized,
    W: AsyncWrite + Unpin,
{
    let bytes = postcard::to_allocvec(value).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("postcard encode failed: {err}"),
        )
    })?;
    w.write_u32_le(bytes.len() as u32).await?;
    w.write_all(&bytes).await?;
    w.flush().await
}

/// Read one length-prefixed postcard frame from `r`.
///
/// Uses [`MAX_FRAME_SIZE`] as the limit; see [`read_framed_with_limit`] for the
/// full behavior. Generic over any [`DeserializeOwned`] type, mirroring
/// [`write_framed`].
pub async fn read_framed<T, R>(r: &mut R) -> io::Result<T>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    read_framed_with_limit(r, MAX_FRAME_SIZE).await
}

/// Read one length-prefixed postcard frame, rejecting a length prefix larger
/// than `max`.
///
/// Returns `UnexpectedEof` if the stream ends mid-frame, and `InvalidData` on
/// a postcard decode failure or a length prefix above `max`. Callers should
/// pass the smallest limit their message type can legitimately need, so a
/// hostile prefix cannot force a large allocation before any validation runs.
pub async fn read_framed_with_limit<T, R>(r: &mut R, max: u32) -> io::Result<T>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    let len = r.read_u32_le().await?;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame length {len} exceeds max {max}"),
        ));
    }
    let mut bytes = vec![0u8; len as usize];
    r.read_exact(&mut bytes).await?;
    postcard::from_bytes(&bytes).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("postcard decode failed: {err}"),
        )
    })
}

/// Write one length-prefixed `PingPong` frame to `w`.
///
/// Thin wrapper over [`write_framed`], preserving the original signature.
pub async fn write_frame<W>(w: &mut W, msg: &PingPong) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_framed(w, msg).await
}

/// Read one length-prefixed `PingPong` frame from `r`.
///
/// Thin wrapper over [`read_framed`], preserving the original signature.
pub async fn read_frame<R>(r: &mut R) -> io::Result<PingPong>
where
    R: AsyncRead + Unpin,
{
    read_framed(r).await
}

#[cfg(test)]
mod tests {
    use super::*;
    // tokio implements AsyncRead/AsyncWrite for std::io::Cursor.
    use std::io::Cursor;

    fn assert_msg_eq(a: &PingPong, b: &PingPong) {
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    #[tokio::test]
    async fn ping_roundtrip() {
        let msg = PingPong::Ping {
            payload: b"hello cawala".to_vec(),
        };
        let mut buf = Cursor::new(Vec::new());
        write_frame(&mut buf, &msg).await.unwrap();

        // Verify the framing: u32 LE length prefix followed by postcard bytes.
        let bytes = buf.get_ref();
        assert_eq!(bytes.len(), 4 + postcard::to_allocvec(&msg).unwrap().len());
        let len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        assert_eq!(len, bytes.len() - 4);

        buf.set_position(0);
        let got = read_frame(&mut buf).await.unwrap();
        assert_msg_eq(&got, &msg);
    }

    #[tokio::test]
    async fn pong_roundtrip() {
        let msg = PingPong::Pong {
            seq: 42,
            payload: b"reply".to_vec(),
        };
        let mut buf = Cursor::new(Vec::new());
        write_frame(&mut buf, &msg).await.unwrap();
        buf.set_position(0);
        let got = read_frame(&mut buf).await.unwrap();
        assert_msg_eq(&got, &msg);
    }

    #[tokio::test]
    async fn empty_payload_roundtrip() {
        for msg in [
            PingPong::Ping { payload: vec![] },
            PingPong::Pong {
                seq: 0,
                payload: vec![],
            },
        ] {
            let mut buf = Cursor::new(Vec::new());
            write_frame(&mut buf, &msg).await.unwrap();
            buf.set_position(0);
            let got = read_frame(&mut buf).await.unwrap();
            assert_msg_eq(&got, &msg);
        }
    }

    #[tokio::test]
    async fn truncated_frame_is_unexpected_eof() {
        // Length prefix claims 5 bytes but only 2 payload bytes follow.
        let mut buf = Cursor::new(vec![5, 0, 0, 0, 1, 2]);
        let err = read_frame(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn garbage_bytes_are_invalid_data() {
        let mut buf = Cursor::new(vec![0xff, 0xff, 0xff, 0xff]); // length > MAX_FRAME_SIZE
        let err = read_frame(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn framed_generic_roundtrip() {
        // A type other than `PingPong` must round-trip through the generic
        // framing helpers, proving the framing is not tied to ping/pong.
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Sample {
            id: u32,
            tags: Vec<String>,
            flag: bool,
        }

        let value = Sample {
            id: 7,
            tags: vec!["a".to_string(), "b".to_string()],
            flag: true,
        };
        let mut buf = Cursor::new(Vec::new());
        write_framed(&mut buf, &value).await.unwrap();
        buf.set_position(0);
        let got: Sample = read_framed(&mut buf).await.unwrap();
        assert_eq!(got, value);

        // A plain `Vec<u32>` round-trips too.
        let nums = vec![1u32, 2, 3, 4];
        let mut buf = Cursor::new(Vec::new());
        write_framed(&mut buf, &nums).await.unwrap();
        buf.set_position(0);
        let got: Vec<u32> = read_framed(&mut buf).await.unwrap();
        assert_eq!(got, nums);

        // An oversized length prefix is rejected as `InvalidData`.
        let mut buf = Cursor::new(vec![0xff, 0xff, 0xff, 0xff]);
        let err = read_framed::<Vec<u32>, _>(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn framed_limit_rejects_oversize() {
        // A length prefix above the caller-supplied limit is rejected before
        // any payload bytes are allocated or read.
        let mut buf = Cursor::new(vec![4, 0, 0, 0, 1, 2, 3, 4]);
        let err = read_framed_with_limit::<Vec<u8>, _>(&mut buf, 2)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // A frame exactly at its own size is accepted.
        let mut buf = Cursor::new(Vec::new());
        write_framed(&mut buf, &vec![1u8, 2]).await.unwrap();
        let frame_len = u32::from_le_bytes(buf.get_ref()[..4].try_into().unwrap());
        buf.set_position(0);
        let got: Vec<u8> = read_framed_with_limit(&mut buf, frame_len).await.unwrap();
        assert_eq!(got, vec![1u8, 2]);
    }
}
