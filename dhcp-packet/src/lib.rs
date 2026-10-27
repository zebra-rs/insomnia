//! DHCPv4 and DHCPv6 packet codec for the insomnia DHCP relay.
//!
//! Pure data: no sockets, no clocks, no global state. The relay
//! daemon (`insomnia-dhcp-relay`) reads datagrams, hands the bytes to
//! [`v4::Packet::parse`] or [`v6::Message::parse`], edits the decoded
//! value and emits it again.
//!
//! Every `parse` is total: any byte string yields `Ok` or `Err`, never a
//! panic, and its work is bounded by the input length. Nothing recurses:
//! a DHCPv6 Relay-Message option stays opaque bytes until the caller
//! parses it explicitly, so a deeply nested Relay-forw costs one level
//! per call. Those properties are what the fuzz targets check.
//!
//! Emitting is canonical rather than byte-preserving: framing that
//! carries no information (DHCPv4 pad options, bytes after the end
//! option) is not kept, and DHCPv4 output is padded to the 300-byte
//! BOOTP minimum. Everything else — option order, unknown options,
//! repeated instances of one option code, `sname` and `file` — survives
//! a parse/emit round trip unchanged.

use std::fmt;

pub mod v4;
pub mod v6;

#[cfg(test)]
mod testutil;

/// Why a byte string is not a well-formed packet, or why a value cannot
/// be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Shorter than the fixed header.
    Short,
    /// An option or sub-option runs past the end of its buffer.
    Truncated,
    /// A value too long for its length field.
    TooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Short => "shorter than the fixed header",
            Error::Truncated => "option runs past the end of the packet",
            Error::TooLong => "value too long for its length field",
        })
    }
}

impl std::error::Error for Error {}
