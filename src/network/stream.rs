//! Application byte-stream halves (W3-H S4, #1164).
//!
//! Production builds: [`StreamSend`] / [`StreamRecv`] ARE the ant-quic
//! stream types (type aliases), so the public API, the generated code and
//! every behaviour are exactly those of ant-quic.
//!
//! Test builds: they are enums over the QUIC halves and the W3-H simulated
//! halves ([`super::sim::SimSend`] / [`super::sim::SimRecv`]), with the
//! inherent methods x0x code calls (`write_all`, `finish`, `read_exact`,
//! `read_to_end`) plus `AsyncRead` / `AsyncWrite`, so the same x0x code
//! compiles and runs over either transport.

#[cfg(not(test))]
/// The send (write) half of an application byte-stream.
pub type StreamSend = ant_quic::HighLevelSendStream;
#[cfg(not(test))]
/// The recv (read) half of an application byte-stream.
pub type StreamRecv = ant_quic::HighLevelRecvStream;

/// Wrap QUIC halves as stream halves (identity in production).
#[cfg(not(test))]
pub(crate) fn from_quic(
    send: ant_quic::HighLevelSendStream,
    recv: ant_quic::HighLevelRecvStream,
) -> (StreamSend, StreamRecv) {
    (send, recv)
}

#[cfg(test)]
pub use self::test_halves::{StreamRecv, StreamSend};

#[cfg(test)]
pub(crate) fn from_quic(
    send: ant_quic::HighLevelSendStream,
    recv: ant_quic::HighLevelRecvStream,
) -> (StreamSend, StreamRecv) {
    (StreamSend::Quic(send), StreamRecv::Quic(recv))
}

#[cfg(test)]
mod test_halves {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    use crate::network::sim::{SimRecv, SimSend};

    /// Send half: QUIC or simulated.
    pub enum StreamSend {
        Quic(ant_quic::HighLevelSendStream),
        Sim(SimSend),
    }

    /// Recv half: QUIC or simulated.
    pub enum StreamRecv {
        Quic(ant_quic::HighLevelRecvStream),
        Sim(SimRecv),
    }

    impl StreamSend {
        /// Write all of `buf` (ant-quic `SendStream::write_all`).
        pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            match self {
                Self::Quic(send) => send.write_all(buf).await.map_err(io::Error::other),
                Self::Sim(send) => AsyncWriteExt::write_all(send, buf).await,
            }
        }

        /// Gracefully end the stream (ant-quic `SendStream::finish`).
        pub fn finish(&mut self) -> io::Result<()> {
            match self {
                Self::Quic(send) => send.finish().map_err(io::Error::other),
                Self::Sim(send) => send.finish(),
            }
        }
    }

    impl StreamRecv {
        /// Fill `buf` exactly (ant-quic `RecvStream::read_exact`).
        pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
            match self {
                Self::Quic(recv) => recv.read_exact(buf).await.map_err(io::Error::other),
                Self::Sim(recv) => AsyncReadExt::read_exact(recv, buf).await.map(|_| ()),
            }
        }

        /// Read to the end of the stream, refusing more than `size_limit`
        /// bytes (ant-quic `RecvStream::read_to_end`).
        pub async fn read_to_end(&mut self, size_limit: usize) -> io::Result<Vec<u8>> {
            match self {
                Self::Quic(recv) => recv.read_to_end(size_limit).await.map_err(io::Error::other),
                Self::Sim(recv) => {
                    let mut out = Vec::new();
                    let limit = u64::try_from(size_limit).unwrap_or(u64::MAX);
                    AsyncReadExt::take(recv, limit.saturating_add(1))
                        .read_to_end(&mut out)
                        .await?;
                    if out.len() > size_limit {
                        return Err(io::Error::other("stream exceeded the size limit"));
                    }
                    Ok(out)
                }
            }
        }
    }

    impl AsyncWrite for StreamSend {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.get_mut() {
                Self::Quic(send) => AsyncWrite::poll_write(Pin::new(send), cx, buf),
                Self::Sim(send) => AsyncWrite::poll_write(Pin::new(send), cx, buf),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.get_mut() {
                Self::Quic(send) => AsyncWrite::poll_flush(Pin::new(send), cx),
                Self::Sim(send) => AsyncWrite::poll_flush(Pin::new(send), cx),
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.get_mut() {
                Self::Quic(send) => AsyncWrite::poll_shutdown(Pin::new(send), cx),
                Self::Sim(send) => AsyncWrite::poll_shutdown(Pin::new(send), cx),
            }
        }
    }

    impl AsyncRead for StreamRecv {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.get_mut() {
                Self::Quic(recv) => AsyncRead::poll_read(Pin::new(recv), cx, buf),
                Self::Sim(recv) => AsyncRead::poll_read(Pin::new(recv), cx, buf),
            }
        }
    }
}
