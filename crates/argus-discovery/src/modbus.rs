//! Modbus/TCP "Read Device Identification" probe (TCP 502) — names the PLC.
//!
//! A port-class guess can say "502 is open, probably a PLC/RTU"; it cannot say
//! *which* controller. This sends exactly one Modbus/TCP request — function code
//! `0x2B` (43) / MEI type `0x0E` (14), **Read Device Identification** — and
//! parses the reply's basic object list into vendor, product code and revision.
//! That turns a generic OT guess into a concrete vendor+model fingerprint
//! (Schneider, Siemens, WAGO, …) for CVE correlation.
//!
//! SAFETY — this is operational technology and the targets may be fragile.
//! Read Device Identification is the **only** function this module ever speaks.
//! It is a pure metadata read: it never reads or writes coils, discrete inputs,
//! holding registers or input registers, and never issues any other function
//! code. One request, one bounded read, no retransmit — nothing here can change
//! a controller's state or flood a sensitive device.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Cap on the response read. A basic device-id reply is an MBAP header plus a
/// short object list; 512 bytes is generous headroom and bounds memory.
const RESPONSE_READ: usize = 512;

/// Function code 43 — Encapsulated Interface Transport.
const FUNC_DEVICE_ID: u8 = 0x2B;
/// MEI type 14 — Read Device Identification.
const MEI_DEVICE_ID: u8 = 0x0E;
/// Read Device ID code 1 — basic object stream (objects 0x00..=0x02).
const READ_DEV_ID_BASIC: u8 = 0x01;
/// Exception responses set the high bit of the function code (`0x2B | 0x80`).
const FUNC_EXCEPTION: u8 = FUNC_DEVICE_ID | 0x80;

/// Basic device-identification object ids.
const OBJ_VENDOR: u8 = 0x00;
const OBJ_PRODUCT_CODE: u8 = 0x01;
const OBJ_REVISION: u8 = 0x02;

/// Unit id `0xFF` — the documented "any/gateway" default; reaches a directly
/// addressed device or a serial-bridging gateway without guessing a slave id.
const UNIT_ID: u8 = 0xFF;

/// What a Read Device Identification exchange told us about a controller.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModbusId {
    /// Object `0x00` — VendorName (e.g. "Schneider Electric").
    pub vendor: Option<String>,
    /// Object `0x01` — ProductCode (e.g. "BMENOC0301").
    pub product_code: Option<String>,
    /// Object `0x02` — MajorMinorRevision (e.g. "3.15").
    pub revision: Option<String>,
}

/// Build the Modbus/TCP Read Device Identification request.
///
/// MBAP header (7 bytes) + PDU:
/// transaction-id `0x0001`, protocol-id `0x0000`, length (unit + PDU),
/// unit-id `0xFF`; PDU = `[0x2B, 0x0E, 0x01, 0x00]` (function, MEI, read-dev-id
/// code = basic, starting object id = 0x00).
fn build_read_device_id() -> Vec<u8> {
    let pdu = [FUNC_DEVICE_ID, MEI_DEVICE_ID, READ_DEV_ID_BASIC, OBJ_VENDOR];
    // length field counts the unit id plus the PDU bytes that follow it.
    let length = 1 + pdu.len();
    let length = u16::try_from(length).unwrap_or(u16::MAX);

    let mut frame = Vec::with_capacity(7 + pdu.len());
    frame.extend_from_slice(&0x0001u16.to_be_bytes()); // transaction id
    frame.extend_from_slice(&0x0000u16.to_be_bytes()); // protocol id
    frame.extend_from_slice(&length.to_be_bytes()); // length
    frame.push(UNIT_ID); // unit id
    frame.extend_from_slice(&pdu);
    frame
}

/// Parse a Read Device Identification response into [`ModbusId`].
///
/// Layout: MBAP header (7 bytes) then the device-id response header
/// (function, MEI, read-dev-id code, conformity level, more-follows,
/// next-object-id, number-of-objects), then `number-of-objects` records of
/// `object-id(1) length(1) value(length)`. Returns `None` for non-Modbus,
/// truncated, or exception (`0x2B | 0x80`) replies, and only yields `Some`
/// once at least one basic object string has been recovered.
fn parse_device_id(resp: &[u8]) -> Option<ModbusId> {
    // MBAP header is fixed at 7 bytes; the PDU begins immediately after it.
    let pdu = resp.get(7..)?;

    let function = *pdu.first()?;
    if function == FUNC_EXCEPTION {
        // The device speaks Modbus but declined the request (illegal function /
        // data). Nothing to fingerprint — treat as "no device id".
        return None;
    }
    if function != FUNC_DEVICE_ID || *pdu.get(1)? != MEI_DEVICE_ID {
        return None;
    }

    // pdu[2] read-dev-id code, pdu[3] conformity level, pdu[4] more-follows,
    // pdu[5] next-object-id, pdu[6] number-of-objects. The object list starts
    // at pdu[7].
    let object_count = usize::from(*pdu.get(6)?);
    let mut pos = 7usize;

    let mut out = ModbusId::default();
    for _ in 0..object_count {
        let object_id = *pdu.get(pos)?;
        let len = usize::from(*pdu.get(pos + 1)?);
        let value_start = pos + 2;
        let value_end = value_start.checked_add(len)?;
        let value = pdu.get(value_start..value_end)?;
        let text = String::from_utf8_lossy(value).trim().to_owned();

        match object_id {
            OBJ_VENDOR => out.vendor = Some(text),
            OBJ_PRODUCT_CODE => out.product_code = Some(text),
            OBJ_REVISION => out.revision = Some(text),
            _ => {}
        }
        pos = value_end;
    }

    if out == ModbusId::default() {
        return None;
    }
    Some(out)
}

/// Probe a Modbus/TCP service: connect, send one Read Device Identification
/// request, parse the reply.
///
/// `wait` bounds the TCP connect, the write and the response read. Returns
/// `None` when the connection or I/O fails, when the peer is not Modbus, or
/// when no basic identification object could be parsed (including exception
/// replies). The request is read-only — see the module-level safety note.
pub async fn query(ip: IpAddr, port: u16, wait: Duration) -> Option<ModbusId> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(wait, TcpStream::connect(addr)).await.ok()?.ok()?;

    let request = build_read_device_id();
    timeout(wait, stream.write_all(&request)).await.ok()?.ok()?;

    let mut buf = vec![0u8; RESPONSE_READ];
    let n = timeout(wait, stream.read(&mut buf)).await.ok()?.ok()?;
    drop(stream);
    if n == 0 {
        return None;
    }

    parse_device_id(&buf[..n])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a basic device-id response: MBAP header + response header +
    /// the given `(object-id, value)` records.
    fn make_response(objects: &[(u8, &[u8])]) -> Vec<u8> {
        let mut pdu = vec![
            FUNC_DEVICE_ID,
            MEI_DEVICE_ID,
            READ_DEV_ID_BASIC,
            0x01,                                 // conformity level
            0x00,                                 // more follows = no
            0x00,                                 // next object id
            u8::try_from(objects.len()).unwrap(), // number of objects
        ];
        for (id, value) in objects {
            pdu.push(*id);
            pdu.push(u8::try_from(value.len()).unwrap());
            pdu.extend_from_slice(value);
        }

        let length = u16::try_from(1 + pdu.len()).unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&0x0001u16.to_be_bytes()); // transaction id
        frame.extend_from_slice(&0x0000u16.to_be_bytes()); // protocol id
        frame.extend_from_slice(&length.to_be_bytes()); // length
        frame.push(UNIT_ID); // unit id
        frame.extend_from_slice(&pdu);
        frame
    }

    #[test]
    fn request_is_a_read_device_id_query() {
        let r = build_read_device_id();
        // MBAP: transaction id 0x0001, protocol id 0x0000.
        assert_eq!(&r[0..2], &[0x00, 0x01], "transaction id");
        assert_eq!(&r[2..4], &[0x00, 0x00], "protocol id must be 0x0000");
        // length = unit id (1) + PDU (4) = 5.
        assert_eq!(&r[4..6], &[0x00, 0x05], "length field");
        assert_eq!(r[6], 0xFF, "unit id");
        // PDU: function 0x2B, MEI 0x0E, read-dev-id code 0x01, object 0x00.
        assert_eq!(r[7], 0x2B, "function code 43");
        assert_eq!(r[8], 0x0E, "MEI type 14");
        assert_eq!(r[9], 0x01, "read device id code = basic");
        assert_eq!(r[10], 0x00, "starting object id");
        assert_eq!(r.len(), 11);
    }

    #[test]
    fn parses_vendor_and_product_code() {
        let resp = make_response(&[
            (0x00, b"Schneider Electric"),
            (0x01, b"BMENOC0301"),
            (0x02, b"3.15"),
        ]);
        let id = parse_device_id(&resp).expect("valid device-id reply parses");
        assert_eq!(id.vendor.as_deref(), Some("Schneider Electric"));
        assert_eq!(id.product_code.as_deref(), Some("BMENOC0301"));
        assert_eq!(id.revision.as_deref(), Some("3.15"));
    }

    #[test]
    fn partial_object_list_still_yields_some() {
        // Only the vendor object present — one string is enough for Some.
        let resp = make_response(&[(0x00, b"WAGO")]);
        let id = parse_device_id(&resp).expect("single object still parses");
        assert_eq!(id.vendor.as_deref(), Some("WAGO"));
        assert_eq!(id.product_code, None);
        assert_eq!(id.revision, None);
    }

    #[test]
    fn exception_response_yields_none() {
        // function 0x2B | 0x80 = 0xAB, exception code 0x01 (illegal function).
        let pdu = [FUNC_EXCEPTION, 0x01];
        let length = u16::try_from(1 + pdu.len()).unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&0x0001u16.to_be_bytes());
        frame.extend_from_slice(&0x0000u16.to_be_bytes());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.push(UNIT_ID);
        frame.extend_from_slice(&pdu);

        assert_eq!(parse_device_id(&frame), None);
    }

    #[test]
    fn truncated_and_non_modbus_replies_yield_none() {
        // Shorter than the MBAP header.
        assert_eq!(parse_device_id(&[0x00, 0x01, 0x00]), None);
        // Right length but wrong function code (not 0x2B, not an exception).
        let mut frame = make_response(&[(0x00, b"X")]);
        frame[7] = 0x03; // overwrite function code with Read Holding Registers
        assert_eq!(parse_device_id(&frame), None);
    }

    #[test]
    fn object_length_overrunning_buffer_yields_none() {
        // Claim a 200-byte value but supply only a few bytes.
        let mut frame = make_response(&[(0x00, b"Schneider Electric")]);
        let last = frame.len() - 18 - 1; // index of the vendor object's length byte
        frame[last] = 200;
        assert_eq!(parse_device_id(&frame), None);
    }
}
