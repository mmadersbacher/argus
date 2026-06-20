//! BACnet/IP device probe (UDP 47808, hand-rolled BVLC/NPDU/APDU, no BACnet crate).
//!
//! Sends a single unconfirmed, READ-ONLY `Who-Is` service to one host and reads
//! the `I-Am` reply. BACnet/IP is the field-bus that ties together building
//! automation — HVAC controllers, lighting panels, access-control and BMS
//! supervisors. The `I-Am` answer carries the controller's BACnet **device
//! object instance** (its address on the network) and its **vendor id** (who
//! built it), which together fingerprint the device.
//!
//! OT-SAFETY: this module only ever emits the unconfirmed `Who-Is` request. It
//! never writes a property, never issues a confirmed service, and sends exactly
//! one datagram with a generous timeout. `Who-Is` is the BACnet equivalent of a
//! broadcast "anyone there?" — passive, read-only, and the standard discovery
//! primitive. Nothing here can change device state.
//!
//! A BACnet/IP frame is three stacked headers (ASHRAE 135, Annex J):
//!   * BVLC  — BACnet Virtual Link Control: `[type, function, length(BE u16)]`.
//!   * NPDU  — network layer: `[version, control, ...optional routing]`.
//!   * APDU  — application layer: the actual service (`Who-Is` / `I-Am`).

use std::net::IpAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Default BACnet/IP UDP port (ASHRAE 135 Annex J, `0xBAC0`).
pub const BACNET_PORT: u16 = 47808;

/// BVLC type byte for BACnet/IP (`0x81`).
const BVLC_TYPE_BIP: u8 = 0x81;
/// BVLC function: Original-Unicast-NPDU (`0x0A`).
const BVLC_FN_UNICAST: u8 = 0x0A;
/// NPDU protocol version (always `0x01`).
const NPDU_VERSION: u8 = 0x01;
/// APDU type nibble for an unconfirmed-request PDU (`0x10`).
const APDU_UNCONFIRMED_REQUEST: u8 = 0x10;
/// Unconfirmed service choice: `Who-Is` (`0x08`).
const SERVICE_WHO_IS: u8 = 0x08;
/// Unconfirmed service choice: `I-Am` (`0x00`).
const SERVICE_I_AM: u8 = 0x00;
/// NPDU control bit indicating the message contains routing information.
const NPDU_CONTROL_DNET: u8 = 0x20;

/// What an `I-Am` reply told us about a building-automation controller.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BacnetDevice {
    /// The BACnet device object instance (low 22 bits of the object id).
    pub device_instance: Option<u32>,
    /// The device's vendor id (last unsigned value in the `I-Am`).
    pub vendor_id: Option<u16>,
}

/// Probe `ip` for a BACnet/IP controller via a unicast `Who-Is`.
///
/// Binds an ephemeral UDP socket, sends one `Who-Is` to `(ip, port)` and waits
/// up to `wait` for the `I-Am`. Returns `Some` only when an `I-Am` with at
/// least a device instance is parsed, otherwise `None`.
pub async fn query(ip: IpAddr, port: u16, wait: Duration) -> Option<BacnetDevice> {
    let sock = UdpSocket::bind(("0.0.0.0", 0)).await.ok()?;
    sock.send_to(&build_who_is(), (ip, port)).await.ok()?;
    let mut buf = [0u8; 1500];
    let (n, _) = timeout(wait, sock.recv_from(&mut buf)).await.ok()?.ok()?;
    parse_i_am(buf.get(..n)?)
}

/// Build the read-only, unbounded `Who-Is` frame (matches every device).
///
/// Result is exactly `[0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08]`: an
/// 8-byte BVLC Original-Unicast-NPDU whose length field equals the frame
/// length, a no-routing NPDU, and an unconfirmed `Who-Is` APDU with no content
/// (an empty range matches all device instances).
fn build_who_is() -> Vec<u8> {
    // APDU: unconfirmed-request PDU + Who-Is service choice, no content.
    let apdu = [APDU_UNCONFIRMED_REQUEST, SERVICE_WHO_IS];
    // NPDU: version + control (0x00 = no routing, no expecting-reply).
    let npdu = [NPDU_VERSION, 0x00];
    // Total frame = BVLC(4) + NPDU + APDU.
    let total = 4 + npdu.len() + apdu.len();
    let len = u16::try_from(total).unwrap_or(u16::MAX);
    let [len_hi, len_lo] = len.to_be_bytes();

    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&[BVLC_TYPE_BIP, BVLC_FN_UNICAST, len_hi, len_lo]);
    frame.extend_from_slice(&npdu);
    frame.extend_from_slice(&apdu);
    frame
}

/// Parse an `I-Am` reply, returning the device instance and vendor id.
///
/// Walks BVLC → NPDU → APDU, confirms the APDU is an unconfirmed `I-Am`, then
/// reads the BACnet application-tagged values. The first tag is the Object
/// Identifier; the remaining tags are walked generically by their tag/length
/// nibble so the vendor id (the last unsigned) is found regardless of the exact
/// max-APDU / segmentation encodings in between.
fn parse_i_am(resp: &[u8]) -> Option<BacnetDevice> {
    let apdu = locate_apdu(resp)?;

    // APDU header: unconfirmed-request PDU type + I-Am service choice.
    if *apdu.first()? != APDU_UNCONFIRMED_REQUEST || *apdu.get(1)? != SERVICE_I_AM {
        return None;
    }
    let tags = apdu.get(2..)?;

    let mut device_instance: Option<u32> = None;
    let mut last_unsigned: Option<u64> = None;
    let mut pos = 0usize;

    while let Some((tag, value, next)) = read_app_tag(tags, pos) {
        // Application-tag number is the high nibble (context tags have bit 3 of
        // the low nibble set; an I-Am only uses application tags so we read the
        // high nibble directly).
        let tag_number = tag >> 4;
        match tag_number {
            // Object Identifier (tag 0xC*, always 4 bytes).
            0xC => {
                if let Some(bytes) = value.get(..4) {
                    let oid = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    // Top 10 bits = object type, low 22 bits = instance number.
                    device_instance = Some(oid & 0x003F_FFFF);
                }
            }
            // Unsigned integer (tag 0x2*): keep the most recent — vendor id is
            // the last unsigned value in the I-Am.
            0x2 => {
                last_unsigned = Some(be_unsigned(value));
            }
            _ => {}
        }
        if next <= pos {
            break; // no forward progress — malformed, stop.
        }
        pos = next;
    }

    let device_instance = device_instance?;
    let vendor_id = last_unsigned.and_then(|v| u16::try_from(v).ok());
    Some(BacnetDevice {
        device_instance: Some(device_instance),
        vendor_id,
    })
}

/// Skip BVLC + NPDU and return the APDU slice, or `None` if malformed.
fn locate_apdu(resp: &[u8]) -> Option<&[u8]> {
    // BVLC: type must be BACnet/IP; length field must cover the datagram.
    if *resp.first()? != BVLC_TYPE_BIP {
        return None;
    }
    let bvlc_len = usize::from(u16::from_be_bytes([*resp.get(2)?, *resp.get(3)?]));
    // Trust the smaller of the declared length and the bytes we actually have.
    let end = bvlc_len.min(resp.len());

    // NPDU starts after the 4-byte BVLC header.
    let npdu = resp.get(4..end)?;
    let control = *npdu.get(1)?;
    // NPDU is at least version+control (2 bytes). If routing info is present
    // (DNET bit), it follows control: DNET(2) + DLEN(1) + DADR(DLEN), then for
    // a reply also Hop Count(1). The common controller reply has control 0x00.
    let mut npdu_pos = 2usize;
    if control & NPDU_CONTROL_DNET != 0 {
        // DNET (2 bytes) + DLEN (1 byte) + DADR (DLEN bytes).
        let dlen = usize::from(*npdu.get(npdu_pos + 2)?);
        npdu_pos = npdu_pos.checked_add(3)?.checked_add(dlen)?;
        // Hop Count for messages carrying routing info.
        npdu_pos = npdu_pos.checked_add(1)?;
    }
    npdu.get(npdu_pos..)
}

/// Read one BACnet application-tagged value at `pos`.
///
/// Returns `(tag_byte, value_slice, next_pos)`. Handles the basic length
/// encoding in the tag's low nibble (0..=4) and the `0x05` extended-length
/// escape (one following length byte). Higher escapes are not needed for the
/// small unsigned/enumerated values an `I-Am` carries.
fn read_app_tag(buf: &[u8], pos: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *buf.get(pos)?;
    let lvt = tag & 0x07; // length/value/type field (low 3 bits)
    let (len, body) = if lvt == 0x05 {
        // Extended length: the real length is in the next byte.
        let ext = usize::from(*buf.get(pos + 1)?);
        (ext, pos + 2)
    } else {
        (usize::from(lvt), pos + 1)
    };
    let end = body.checked_add(len)?;
    let value = buf.get(body..end)?;
    Some((tag, value, end))
}

/// Decode a big-endian BACnet unsigned (1..=8 bytes) into a `u64`.
fn be_unsigned(bytes: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for &b in bytes.iter().take(8) {
        v = (v << 8) | u64::from(b);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn who_is_frame_is_exact_and_length_matches() {
        let frame = build_who_is();
        assert_eq!(frame, vec![0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08]);
        // BVLC length field (bytes 2..4, big-endian) equals the full frame length.
        let declared = u16::from_be_bytes([frame[2], frame[3]]);
        assert_eq!(usize::from(declared), frame.len());
        assert_eq!(declared, 0x0008);
    }

    /// Hand-build an I-Am for device instance 1001 (0x0003E9), vendor id 8.
    fn make_i_am(object_id: u32, max_apdu: u16, segmentation: u8, vendor: u16) -> Vec<u8> {
        // APDU: 0x10 (unconfirmed) + 0x00 (I-Am), then 4 application tags.
        let mut apdu = vec![APDU_UNCONFIRMED_REQUEST, SERVICE_I_AM];

        // 1) Object Identifier: tag 0xC4 (app tag 12, length 4) + 4 BE bytes.
        apdu.push(0xC4);
        apdu.extend_from_slice(&object_id.to_be_bytes());

        // 2) Max APDU length accepted: unsigned, tag 0x22 (app tag 2, length 2).
        apdu.push(0x22);
        apdu.extend_from_slice(&max_apdu.to_be_bytes());

        // 3) Segmentation supported: enumerated, tag 0x91 (app tag 9, length 1).
        apdu.push(0x91);
        apdu.push(segmentation);

        // 4) Vendor ID: unsigned, tag 0x21 (app tag 2, length 1) — small vendor.
        apdu.push(0x21);
        apdu.push(u8::try_from(vendor).unwrap_or(0));

        // NPDU: version + control (no routing).
        let npdu = [NPDU_VERSION, 0x00];

        let total = 4 + npdu.len() + apdu.len();
        let len = u16::try_from(total).unwrap_or(u16::MAX);
        let [len_hi, len_lo] = len.to_be_bytes();

        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&[BVLC_TYPE_BIP, BVLC_FN_UNICAST, len_hi, len_lo]);
        frame.extend_from_slice(&npdu);
        frame.extend_from_slice(&apdu);
        frame
    }

    #[test]
    fn parses_device_instance_and_vendor() {
        // object id = (8 << 22) | 1001 = 0x020003E9 → device instance 1001.
        let object_id = (8u32 << 22) | 0x3E9;
        assert_eq!(object_id, 0x0200_03E9);
        let frame = make_i_am(object_id, 1476, 3, 8);

        let dev = parse_i_am(&frame).expect("I-Am must parse");
        assert_eq!(dev.device_instance, Some(1001));
        assert_eq!(dev.vendor_id, Some(8));
    }

    #[test]
    fn object_identifier_masks_off_object_type() {
        // A non-device object-type in the top 10 bits must not leak into the
        // instance number. type 12 (some non-device) | instance 4194303 (max).
        let object_id = (12u32 << 22) | 0x003F_FFFF;
        let frame = make_i_am(object_id, 480, 0, 260);
        let dev = parse_i_am(&frame).expect("I-Am must parse");
        assert_eq!(dev.device_instance, Some(0x003F_FFFF));
    }

    #[test]
    fn vendor_id_handles_two_byte_unsigned() {
        // Vendor id 260 needs two bytes (0x0104); tag 0x22 (length 2).
        let mut apdu = vec![APDU_UNCONFIRMED_REQUEST, SERVICE_I_AM];
        apdu.push(0xC4);
        apdu.extend_from_slice(&((8u32 << 22) | 0x3E9).to_be_bytes());
        apdu.push(0x22);
        apdu.extend_from_slice(&480u16.to_be_bytes()); // max apdu
        apdu.push(0x91);
        apdu.push(0); // segmentation
        apdu.push(0x22);
        apdu.extend_from_slice(&260u16.to_be_bytes()); // vendor id 260

        let npdu = [NPDU_VERSION, 0x00];
        let total = 4 + npdu.len() + apdu.len();
        let len = u16::try_from(total).unwrap_or(u16::MAX);
        let [hi, lo] = len.to_be_bytes();
        let mut frame = vec![BVLC_TYPE_BIP, BVLC_FN_UNICAST, hi, lo];
        frame.extend_from_slice(&npdu);
        frame.extend_from_slice(&apdu);

        let dev = parse_i_am(&frame).expect("I-Am must parse");
        assert_eq!(dev.device_instance, Some(1001));
        assert_eq!(dev.vendor_id, Some(260));
    }

    #[test]
    fn rejects_non_i_am_service() {
        // Same shape but service choice 0x08 (Who-Is) instead of I-Am.
        let mut frame = make_i_am((8u32 << 22) | 0x3E9, 1476, 3, 8);
        // APDU service-choice is at BVLC(4) + NPDU(2) + 1 = byte 7.
        frame[7] = SERVICE_WHO_IS;
        assert!(parse_i_am(&frame).is_none());
    }

    #[test]
    fn rejects_garbage_and_short_frames() {
        assert!(parse_i_am(&[]).is_none());
        assert!(parse_i_am(&[0x81, 0x0A, 0x00, 0x04]).is_none());
        assert!(parse_i_am(&[0x00; 16]).is_none());
    }

    #[test]
    fn parses_i_am_with_npdu_routing_info() {
        // I-Am from a router: NPDU control has the DNET bit set, so SNET/SLEN/
        // SADR + Hop Count precede the APDU. Build it and confirm we skip them.
        let object_id = (8u32 << 22) | 0x3E9;
        let mut apdu = vec![APDU_UNCONFIRMED_REQUEST, SERVICE_I_AM];
        apdu.push(0xC4);
        apdu.extend_from_slice(&object_id.to_be_bytes());
        apdu.push(0x22);
        apdu.extend_from_slice(&480u16.to_be_bytes());
        apdu.push(0x91);
        apdu.push(0);
        apdu.push(0x21);
        apdu.push(8);

        // NPDU with routing: version, control=0x20, DNET(2), DLEN=2, DADR(2),
        // Hop Count(1).
        let mut npdu = vec![NPDU_VERSION, NPDU_CONTROL_DNET];
        npdu.extend_from_slice(&[0x00, 0x01]); // DNET
        npdu.push(0x02); // DLEN
        npdu.extend_from_slice(&[0xAA, 0xBB]); // DADR
        npdu.push(0xFF); // Hop Count

        let total = 4 + npdu.len() + apdu.len();
        let len = u16::try_from(total).unwrap_or(u16::MAX);
        let [hi, lo] = len.to_be_bytes();
        let mut frame = vec![BVLC_TYPE_BIP, BVLC_FN_UNICAST, hi, lo];
        frame.extend_from_slice(&npdu);
        frame.extend_from_slice(&apdu);

        let dev = parse_i_am(&frame).expect("routed I-Am must parse");
        assert_eq!(dev.device_instance, Some(1001));
        assert_eq!(dev.vendor_id, Some(8));
    }
}
