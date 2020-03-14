#include <upfnetworklib/gtp_u_encap.hh>

namespace UPF {
namespace NetworkLib {

/**
 * This is the raw data used to initialize the Ethernet + IPV4 + UDP +
 * GTPv1-U headers each time we encapsulate IPv4 data.
 */
const std::array<unsigned char, GTPv1UEthEncap::totalHeaderLength>
    GTPv1UEthEncap::headerInitData{
        /////////////////////
        // Ethernet header //
        /////////////////////

        // Dst MAC address
        // Offset: 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // Src MAC address
        // Offset: 6
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // EtherType (0x0800 = IPv4)
        // Offset: 12
        0x08, 0x00,

        /////////////////
        // IPv4 header //
        /////////////////

        // Version + header length
        // Offset: 14
        0x45,

        // Differentiated services
        // Offset: 15
        0x00,

        // Total length
        // Offset: 16
        0x00, 0x00,

        // Identification
        // Offset: 18
        0x00, 0x00,

        // Flags (no flags)
        // Offset: 20
        0x00, 0x00,

        // TTL (64 hops)
        // Offset: 22
        0x40,

        // Protocol type (0x11 = UDP)
        // Offset: 23
        //
        // Note: if you change this, please also update
        //       computeAndSetChecksums()
        0x11,

        // IPv4 header checksum
        // Offset: 24
        0x00, 0x00,

        // IPv4 source address
        // Offset: 26
        0x00, 0x00, 0x00, 0x00,

        // IPv4 destination address
        // Offset: 30
        0x00, 0x00, 0x00, 0x00,

        ////////////////
        // UDP header //
        ////////////////

        // Source port (0x0868 = 2152, the standard GTPv1-U port)
        // Offset: 34
        // Note: if you change this, update the doc on setSrcPort()
        0x08, 0x68,

        // Destinatin port (0x0868 = 2152, the standard GTPv1-U port)
        // Offset: 36
        // Note: if you change this, update the doc on setDstPort()
        0x08, 0x68,

        // Total length
        // Offset: 38
        0x00, 0x00,

        // Header checksum
        // Offset: 40
        0x00, 0x00,

        ////////////////////
        // GTPv1-U header //
        ////////////////////

        // Flags (0x38 == version 1, proto 1, reserved 1, no extra fields)
        // Offset: 42
        0x38,

        // Message type (0xff = T-PDU)
        // Offset: 43
        0xff,

        // Message length
        // Offset: 44
        0x00, 0x00,

        // TEID
        // Offset: 46
        0x00, 0x00, 0x00, 0x00};

GTPv1UEthEncap &
GTPv1UEthEncap::setPayload(const NetworkLib::BufferView &ipv4Data) {
    // Note: we assume that ipv4Data.size() has the same value as
    //       the length in the IPv4 header. We don't check this.

    // Check if the packet isn't too big
    if (ipv4Data.size() > maxPayloadLength) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": called with BufferView.size() == " << ipv4Data.size()
            << " (max allowed payload size for GTPv1-U encap is "
            << maxPayloadLength << ')';
        throw std::length_error(err.str());
    }

    // Check if there's enough room
    if (ipv4Data.size() > mPayloadArea.size()) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": called with BufferView.size() == " << ipv4Data.size()
            << " (max size is " << mPayloadArea.size() << ')';
        throw std::length_error(err.str());
    }

    // Copy the payload (we already checked size above)
    unsigned char *p = mPayloadArea.getUnderlyingWritableBufferPtr();
    ipv4Data.copyTo(0, ipv4Data.size(), p);

    // Keep track of the payload actual length
    mPayloadActualLength = ipv4Data.size();

    //////////////////////////////
    // Update lengths in buffer //
    //////////////////////////////

    // Set the GTPv1-U data length
    const std::uint16_t gtpMessageLength = mPayloadActualLength;
    mBufferWritableView.setUint16At_nocheck(gtp_messageLengthOffset,
                                            gtpMessageLength);

    // Set the UDP total length
    const std::uint16_t udpTotLen =
        gtpMessageLength + gtp_headerLength + udp_headerLength;
    mBufferWritableView.setUint16At_nocheck(udp_totalLengthOffset, udpTotLen);

    // Set the IPv4 total length
    mBufferWritableView.setUint16At_nocheck(ipv4_totalLengthOffset,
                                            udpTotLen + ipv4_headerLength);

    // At this point, the complete Ethernet frame with encapsulated
    // data ranges from the start of the composition buffer up to the
    // end of the encapsulated IPv4 data (we still have to compute
    // checksums, though).
    mEthFrame =
        mBufferWritableView.getSub(0, totalHeaderLength + ipv4Data.size());

    return *this;
}

GTPv1UEthEncap &GTPv1UEthEncap::setPayload() {
    // Check and complain if the data at the expected payload offset
    // doesn't look like an IPV4 packet. Here we check that the
    // expected IPv4 version is actually a 4.
    //
    // Note:
    if ((mBufferWritableView.size() > payload_startOffset) &&
        (((mBufferWritableView.getUint8At_nocheck(payload_startOffset) >> 4) &
          0x0F) != 4)) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": called with non-IPv4 payload";
        throw std::runtime_error(err.str());
    }

    // Keep track of the payload actual length.
    // (we already checked that mBufferWritableView().size >= totalHeaderLength
    // on construction -- see call to throwIfBufferIsUnsuitable())
    mPayloadActualLength = mBufferWritableView.size() - totalHeaderLength;

    //////////////////////////////
    // Update lengths in buffer //
    //////////////////////////////

    // Set the GTPv1-U data length
    const std::uint16_t gtpMessageLength = mPayloadActualLength;
    mBufferWritableView.setUint16At_nocheck(gtp_messageLengthOffset,
                                            gtpMessageLength);

    // Set the UDP total length
    const std::uint16_t udpTotLen =
        gtpMessageLength + gtp_headerLength + udp_headerLength;
    mBufferWritableView.setUint16At_nocheck(udp_totalLengthOffset, udpTotLen);

    // Set the IPv4 total length
    mBufferWritableView.setUint16At_nocheck(ipv4_totalLengthOffset,
                                            udpTotLen + ipv4_headerLength);

    // At this point, the complete Ethernet frame with encapsulated
    // data ranges *exactly* from the start to the end of the
    // composition buffer (we still have to compute checksums,
    // though).
    mEthFrame = mBufferWritableView;

    return *this;
}

GTPv1UEthEncap &GTPv1UEthEncap::computeAndSetChecksums() {

    // Base pointer to buffer's data.
    const unsigned char *const b = mBufferWritableView.getUnderlyingBufferPtr();

    // Total UDP length (UDP header + GTPv1-U header + payload actual length)
    const std::uint32_t udpTotalLen =
        (b[udp_totalLengthOffset] << 8) + b[udp_totalLengthOffset + 1];

    const std::uint32_t udpHdrSum =

        // Source port
        (b[udp_srcPortOffset] << 8) +
        b[udp_srcPortOffset + 1]

        // Destination port
        + (b[udp_dstPortOffset] << 8) +
        b[udp_dstPortOffset + 1]

        // Total UDP length (UDP header + GTPv1-U header + payload actual
        // length)
        + udpTotalLen;

    // Then, compute the sum for the UDP pseudo-header

    // First, a partial sum (that will be reused in computing the IPv4
    // header checksum)
    const std::uint32_t udpPseudoHdrSum_nolength =
        // Source address
        (b[ipv4_srcAddressOffset + 0] << 8) + b[ipv4_srcAddressOffset + 1] +
        (b[ipv4_srcAddressOffset + 2] << 8) +
        b[ipv4_srcAddressOffset + 3]

        // Destination address
        + (b[ipv4_dstAddressOffset + 0] << 8) + b[ipv4_dstAddressOffset + 1] +
        (b[ipv4_dstAddressOffset + 2] << 8) +
        b[ipv4_dstAddressOffset + 3]

        // Protocol (0x11 == UDP)
        + 0x11;

    // Then the full sum
    const std::uint32_t udpPseudoHdrSum =

        // The partial sum...
        udpPseudoHdrSum_nolength

        // ... plus the total UDP length (again)
        + udpTotalLen;

    //////////////////
    // UDP checksum //
    //////////////////

    if (mEnableUDPChecksum) {
        // Make a view out of the GTPv1-U header + the IPV4 payload (which are
        // the UDP payload).
        BufferView bv = mBufferWritableView.getSub(
            gtp_startOffset, mPayloadActualLength + gtp_headerLength);
        const std::uint32_t payloadSum = bv.getSum16();

        // Sum everything
        std::uint32_t udpSum = udpPseudoHdrSum + udpHdrSum + payloadSum;

        // Reduce to 16-bit value
        while ((udpSum >> 16) != 0) {
            udpSum = (udpSum & 0xFFFF) + (udpSum >> 16);
        }

        // Do 1's complement, unless it would result in a zero.
        std::uint16_t udpChecksum = udpSum;
        if (udpChecksum != 0xFFFF) {
            udpChecksum = ~udpChecksum;
        }

        // Store the UDP checksum
        mBufferWritableView.setUint16At_nocheck(udp_checksumOffset,
                                                udpChecksum);
    }

    // Note: if UDP checksum is not enabled, the checksum field is
    //       already filled with 0x0000 meaning that no UDP checksum
    //       is specified.

    //////////////////////////
    // IPv4 header checksum //
    //////////////////////////

    std::uint32_t ipv4HdrSum =
        (b[ipv4_startOffset + 0] << 8) + b[ipv4_startOffset + 1] +
        (b[ipv4_startOffset + 2] << 8) + b[ipv4_startOffset + 3] +
        (b[ipv4_startOffset + 4] << 8) + b[ipv4_startOffset + 5] +
        (b[ipv4_startOffset + 6] << 8) + b[ipv4_startOffset + 7] +
        (b[ipv4_startOffset + 8] << 8)

        // Skip the checksum field, and reuse the
        // partial sum from the UDP pseudo header
        + udpPseudoHdrSum_nolength;

    // Reduce to 16-bit value
    while ((ipv4HdrSum >> 16) != 0) {
        ipv4HdrSum = (ipv4HdrSum & 0xFFFF) + (ipv4HdrSum >> 16);
    }

    // Do 1's complement, unless it would result in a zero.
    std::uint16_t ipv4HdrChecksum = ipv4HdrSum;
    if (ipv4HdrChecksum != 0xFFFF) {
        ipv4HdrChecksum = ~ipv4HdrChecksum;
    }

    // store checksum
    mBufferWritableView.setUint16At_nocheck(ipv4_checksumOffset,
                                            ipv4HdrChecksum);

    return *this;
}

/**
 * This is the raw data used to initialize the IPV4 + UDP +
 * GTPv1-U headers each time we encapsulate IPv4 data.
 */
const std::array<unsigned char, GTPv1UIPv4Encap::totalHeaderLength>
    GTPv1UIPv4Encap::headerInitData{
        /////////////////
        // IPv4 header //
        /////////////////

        // Version + header length
        // Offset: 0
        0x45,

        // Differentiated services
        // Offset: 1
        0x00,

        // Total length
        // Offset: 2
        0x00, 0x00,

        // Identification
        // Offset: 4
        0x00, 0x00,

        // Flags (no flags)
        // Offset: 6
        0x00, 0x00,

        // TTL (64 hops)
        // Offset: 8
        0x40,

        // Protocol type (0x11 = UDP)
        // Offset: 9
        //
        // Note: if you change this, please also update
        //       computeAndSetChecksums()
        0x11,

        // IPv4 header checksum
        // Offset: 10
        0x00, 0x00,

        // IPv4 source address
        // Offset: 12
        0x00, 0x00, 0x00, 0x00,

        // IPv4 destination address
        // Offset: 16
        0x00, 0x00, 0x00, 0x00,

        ////////////////
        // UDP header //
        ////////////////

        // Source port (0x0868 = 2152, the standard GTPv1-U port)
        // Offset: 20
        // Note: if you change this, update the doc on setSrcPort()
        0x08, 0x68,

        // Destinatin port (0x0868 = 2152, the standard GTPv1-U port)
        // Offset: 22
        // Note: if you change this, update the doc on setDstPort()
        0x08, 0x68,

        // Total length
        // Offset: 24
        0x00, 0x00,

        // Header checksum
        // Offset: 26
        0x00, 0x00,

        ////////////////////
        // GTPv1-U header //
        ////////////////////

        // Flags (0x38 == version 1, proto 1, reserved 1, no extra fields)
        // Offset: 28
        0x38,

        // Message type (0xff = T-PDU)
        // Offset: 29
        0xff,

        // Message length
        // Offset: 30
        0x00, 0x00,

        // TEID
        // Offset: 32
        0x00, 0x00, 0x00, 0x00};

GTPv1UIPv4Encap &
GTPv1UIPv4Encap::setPayload(const NetworkLib::BufferView &ipv4Data) {
    // Note: we assume that ipv4Data.size() has the same value as
    //       the length in the IPv4 header. We don't check this.

    // Check if the packet isn't too big
    if (ipv4Data.size() > maxPayloadLength) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": called with BufferView.size() == " << ipv4Data.size()
            << " (max allowed payload size for GTPv1-U encap is "
            << maxPayloadLength << ')';
        throw std::length_error(err.str());
    }

    // Check if there's enough room
    if (ipv4Data.size() > mPayloadArea.size()) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": called with BufferView.size() == " << ipv4Data.size()
            << " (max size is " << mPayloadArea.size() << ')';
        throw std::length_error(err.str());
    }

    // Copy the payload (we already checked size above)
    unsigned char *p = mPayloadArea.getUnderlyingWritableBufferPtr();
    ipv4Data.copyTo(0, ipv4Data.size(), p);

    // Keep track of the payload actual length
    mPayloadActualLength = ipv4Data.size();

    //////////////////////////////
    // Update lengths in buffer //
    //////////////////////////////

    // Set the GTPv1-U data length
    const std::uint16_t gtpMessageLength = mPayloadActualLength;
    mBufferWritableView.setUint16At_nocheck(gtp_messageLengthOffset,
                                            gtpMessageLength);

    // Set the UDP total length
    const std::uint16_t udpTotLen =
        gtpMessageLength + gtp_headerLength + udp_headerLength;
    mBufferWritableView.setUint16At_nocheck(udp_totalLengthOffset, udpTotLen);

    // Set the IPv4 total length
    mBufferWritableView.setUint16At_nocheck(ipv4_totalLengthOffset,
                                            udpTotLen + ipv4_headerLength);

    // At this point, the complete IPv4 packet with encapsulated
    // data ranges from the start of the composition buffer up to the
    // end of the encapsulated IPv4 data (we still have to compute
    // checksums, though).
    mIPv4Packet =
        mBufferWritableView.getSub(0, totalHeaderLength + ipv4Data.size());

    return *this;
}

GTPv1UIPv4Encap &GTPv1UIPv4Encap::setPayload() {
    // Check and complain if the data at the expected payload offset
    // doesn't look like an IPV4 packet. Here we check that the
    // expected IPv4 version is actually a 4.
    //
    // Note:
    if ((mBufferWritableView.size() > payload_startOffset) &&
        (((mBufferWritableView.getUint8At_nocheck(payload_startOffset) >> 4) &
          0x0F) != 4)) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": called with non-IPv4 payload";
        throw std::runtime_error(err.str());
    }

    // Keep track of the payload actual length.
    // (we already checked that mBufferWritableView().size >= totalHeaderLength
    // on construction -- see call to throwIfBufferIsUnsuitable())
    mPayloadActualLength = mBufferWritableView.size() - totalHeaderLength;

    //////////////////////////////
    // Update lengths in buffer //
    //////////////////////////////

    // Set the GTPv1-U data length
    const std::uint16_t gtpMessageLength = mPayloadActualLength;
    mBufferWritableView.setUint16At_nocheck(gtp_messageLengthOffset,
                                            gtpMessageLength);

    // Set the UDP total length
    const std::uint16_t udpTotLen =
        gtpMessageLength + gtp_headerLength + udp_headerLength;
    mBufferWritableView.setUint16At_nocheck(udp_totalLengthOffset, udpTotLen);

    // Set the IPv4 total length
    mBufferWritableView.setUint16At_nocheck(ipv4_totalLengthOffset,
                                            udpTotLen + ipv4_headerLength);

    // At this point, the complete IPv4 packet with encapsulated
    // data ranges *exactly* from the start to the end of the
    // composition buffer (we still have to compute checksums,
    // though).
    mIPv4Packet = mBufferWritableView;

    return *this;
}

GTPv1UIPv4Encap &GTPv1UIPv4Encap::computeAndSetChecksums() {

    // Base pointer to buffer's data.
    const unsigned char *const b = mBufferWritableView.getUnderlyingBufferPtr();

    // Total UDP length (UDP header + GTPv1-U header + payload actual length)
    const std::uint32_t udpTotalLen =
        (b[udp_totalLengthOffset] << 8) + b[udp_totalLengthOffset + 1];

    const std::uint32_t udpHdrSum =

        // Source port
        (b[udp_srcPortOffset] << 8) +
        b[udp_srcPortOffset + 1]

        // Destination port
        + (b[udp_dstPortOffset] << 8) +
        b[udp_dstPortOffset + 1]

        // Total UDP length (UDP header + GTPv1-U header + payload actual
        // length)
        + udpTotalLen;

    // Then, compute the sum for the UDP pseudo-header

    // First, a partial sum (that will be reused in computing the IPv4
    // header checksum)
    const std::uint32_t udpPseudoHdrSum_nolength =
        // Source address
        (b[ipv4_srcAddressOffset + 0] << 8) + b[ipv4_srcAddressOffset + 1] +
        (b[ipv4_srcAddressOffset + 2] << 8) +
        b[ipv4_srcAddressOffset + 3]

        // Destination address
        + (b[ipv4_dstAddressOffset + 0] << 8) + b[ipv4_dstAddressOffset + 1] +
        (b[ipv4_dstAddressOffset + 2] << 8) +
        b[ipv4_dstAddressOffset + 3]

        // Protocol (0x11 == UDP)
        + 0x11;

    // Then the full sum
    const std::uint32_t udpPseudoHdrSum =

        // The partial sum...
        udpPseudoHdrSum_nolength

        // ... plus the total UDP length (again)
        + udpTotalLen;

    //////////////////
    // UDP checksum //
    //////////////////

    if (mEnableUDPChecksum) {
        // Make a view out of the GTPv1-U header + the IPV4 payload (which are
        // the UDP payload).
        BufferView bv = mBufferWritableView.getSub(
            gtp_startOffset, mPayloadActualLength + gtp_headerLength);
        const std::uint32_t payloadSum = bv.getSum16();

        // Sum everything
        std::uint32_t udpSum = udpPseudoHdrSum + udpHdrSum + payloadSum;

        // Reduce to 16-bit value
        while ((udpSum >> 16) != 0) {
            udpSum = (udpSum & 0xFFFF) + (udpSum >> 16);
        }

        // Do 1's complement, unless it would result in a zero.
        std::uint16_t udpChecksum = udpSum;
        if (udpChecksum != 0xFFFF) {
            udpChecksum = ~udpChecksum;
        }

        // Store the UDP checksum
        mBufferWritableView.setUint16At_nocheck(udp_checksumOffset,
                                                udpChecksum);
    }

    // Note: if UDP checksum is not enabled, the checksum field is
    //       already filled with 0x0000 meaning that no UDP checksum
    //       is specified.

    //////////////////////////
    // IPv4 header checksum //
    //////////////////////////

    std::uint32_t ipv4HdrSum =
        (b[ipv4_startOffset + 0] << 8) + b[ipv4_startOffset + 1] +
        (b[ipv4_startOffset + 2] << 8) + b[ipv4_startOffset + 3] +
        (b[ipv4_startOffset + 4] << 8) + b[ipv4_startOffset + 5] +
        (b[ipv4_startOffset + 6] << 8) + b[ipv4_startOffset + 7] +
        (b[ipv4_startOffset + 8] << 8)

        // Skip the checksum field, and reuse the
        // partial sum from the UDP pseudo header
        + udpPseudoHdrSum_nolength;

    // Reduce to 16-bit value
    while ((ipv4HdrSum >> 16) != 0) {
        ipv4HdrSum = (ipv4HdrSum & 0xFFFF) + (ipv4HdrSum >> 16);
    }

    // Do 1's complement, unless it would result in a zero.
    std::uint16_t ipv4HdrChecksum = ipv4HdrSum;
    if (ipv4HdrChecksum != 0xFFFF) {
        ipv4HdrChecksum = ~ipv4HdrChecksum;
    }

    // store checksum
    mBufferWritableView.setUint16At_nocheck(ipv4_checksumOffset,
                                            ipv4HdrChecksum);

    return *this;
}

} // namespace NetworkLib
} // namespace UPF
