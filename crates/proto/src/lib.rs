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

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod addr;

pub use addr::{OctAddr, ParseOctAddrError, MAX_SLOT};

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

fn encode(msg: &PingPong) -> Result<Vec<u8>, io::Error> {
    postcard::to_allocvec(msg).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("postcard encode failed: {err}"),
        )
    })
}

fn decode(bytes: &[u8]) -> Result<PingPong, io::Error> {
    postcard::from_bytes(bytes).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("postcard decode failed: {err}"),
        )
    })
}

/// Write one length-prefixed `PingPong` frame to `w`.
///
/// Frame layout: `u32` LE byte-length followed by the postcard-encoded
/// message bytes.
pub async fn write_frame<W>(w: &mut W, msg: &PingPong) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let bytes = encode(msg)?;
    w.write_u32_le(bytes.len() as u32).await?;
    w.write_all(&bytes).await?;
    w.flush().await
}

/// Read one length-prefixed `PingPong` frame from `r`.
///
/// Returns `UnexpectedEof` if the stream ends mid-frame, and `InvalidData` on
/// a postcard decode failure or an oversized length prefix.
pub async fn read_frame<R>(r: &mut R) -> io::Result<PingPong>
where
    R: AsyncRead + Unpin,
{
    let len = r.read_u32_le().await?;
    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame length {len} exceeds max {MAX_FRAME_SIZE}"),
        ));
    }
    let mut bytes = vec![0u8; len as usize];
    r.read_exact(&mut bytes).await?;
    decode(&bytes)
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
}
