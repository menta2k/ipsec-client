//! Length-prefixed JSON framing: `u32 LE length | UTF-8 JSON`.

use crate::messages::Frame;
use std::io::{self, Read, Write};

/// Largest accepted frame body (1 MiB).
pub const MAX_FRAME: usize = 1_048_576;

/// Serialize and write one frame (single `write_all` so frames never interleave).
pub fn write_frame<W: Write>(w: &mut W, frame: &Frame) -> io::Result<()> {
    let body =
        serde_json::to_vec(frame).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
    buf.extend_from_slice(&body);
    w.write_all(&buf)?;
    w.flush()
}

/// Read one frame. Oversized or unparseable frames are `InvalidData` errors;
/// a clean EOF before the length prefix is `UnexpectedEof`.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Frame> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds 1 MiB",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{Event, Request};
    use std::io::Cursor;

    #[test]
    fn roundtrip() {
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &Frame::Request {
                body: Request::GetStatus,
            },
        )
        .unwrap();
        write_frame(
            &mut buf,
            &Frame::Event {
                body: Event::ProfilesChanged,
            },
        )
        .unwrap();
        let mut c = Cursor::new(buf);
        assert_eq!(
            read_frame(&mut c).unwrap(),
            Frame::Request {
                body: Request::GetStatus
            }
        );
        assert_eq!(
            read_frame(&mut c).unwrap(),
            Frame::Event {
                body: Event::ProfilesChanged
            }
        );
        assert_eq!(
            read_frame(&mut c).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn rejects_oversize_without_allocating() {
        let mut c = Cursor::new(((MAX_FRAME + 1) as u32).to_le_bytes().to_vec());
        assert_eq!(
            read_frame(&mut c).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn rejects_short_and_garbage() {
        let mut short = 10u32.to_le_bytes().to_vec();
        short.extend_from_slice(b"abc");
        assert_eq!(
            read_frame(&mut Cursor::new(short)).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        let mut garbage = 5u32.to_le_bytes().to_vec();
        garbage.extend_from_slice(b"{{{{{");
        assert_eq!(
            read_frame(&mut Cursor::new(garbage)).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
