#ifndef UPFNETWORKLIB_GTPENCAP_HH
#define UPFNETWORKLIB_GTPENCAP_HH

// For BufferWritableView
#include <upfnetworklib/buffers.hh>

// For Port::Number
#include <upfnetworklib/ipv4.hh>

// For GTP_TEID
#include <upfnetworklib/gtp_u.hh>

// For std::array<T,s>
#include <array>

// For ostringstream
#include <sstream>

namespace UPF {
namespace NetworkLib {

/**
 * @brief A class that encapsulates a IPv4 payload in a Ethernet
 *        frame, using GTPv1-U on IPv4.
 *
 * The Ethernet frame is composed inside the BufferWritableView given on
 * construction.
 *
 * There are 2 ways this can be done:
 *
 * 1. The simple, but less efficient way (data is copied)
 *
 *    The (encapsualtion) buffer passed to the constructor is assumed
 *    to contain nothing relevant: it is just large enough to contain
 *    the encapsulation headers and the IPv4 payload (or larger).
 *
 *    1. First, call init() to copy the boilerplate encapsulation
 *       headers;
 *
 *    2. Then, call 'setSrcMACAddress(const NetworkLib::MACAddress&)',
 *       'setDstMACAddress(const NetworkLib::MACAddress&)', etc. up to
 *       'setTEID(NetworkLib::GTP_TEID::Number)' to set all the fields
 *       needed for encapsulation;
 *
 *    3. Then call 'setPayload(const BufferView&)' with a BufferView
 *       specifying the IPv4 data to be encapsulated, which is
 *       **copied** into the encapsulation buffer.
 *
 *    4. Finally, call 'computeAndSetChecksums()', and you are done:
 *       the final ethernet frame can be obtained by calling
 *       'getEthFrame()'.
 *
 * 2. The slighly less simple, but more efficient way (no data is copied)
 *
 *    The encapsulation buffer passed to the constructor is expected
 *    to contain the IPv4 data to be encapsulated **starting from
 *    offset 'GTPv1UEncap::payload_startOffset' (normally `50`).
 *
 *    Bytes 0-49 are overwritten with a simple Ethernet header (14
 *    bytes), a simple IPv4 header (20 bytes), a UDP header (8 bytes)
 *    and a GTPv1-U header (8 bytes). The size of this
 *    BufferWritableView must be exactly GTPv1UEncap::payload_startOffset bytes
 * + the actual length of the IPv4 packet to encapsulate, no more, no less.
 *
 *    1. First, call init() to copy the boilerplate encapsulation
 *       headers (same as the other way);
 *
 *    2. Then, call 'setSrcMACAddress(const NetworkLib::MACAddress&)',
 *       'setDstMACAddress(const NetworkLib::MACAddress&)', etc. up to
 *       'setTEID(NetworkLib::GTP_TEID::Number)' to set all the fields
 *       needed for encapsulation (same as the other way);
 *
 *    3. Then call 'setPayload()' **with no arguments**, which just
 *       updates things in the encapsulation buffer, **without copying
 *       anything**, as the payload is already there.
 *
 *    4. Finally, call 'computeAndSetChecksums()', and you are done:
 *       the final ethernet frame can be obtained by calling
 *       'getEthFrame()' (same as the other way).
 *
 * Computing the UDP checksum can be disabled (see
 * 'enableUDPChecksum(bool)').
 */
class GTPv1UEthEncap {
  public:
    ///@name Constructors

    /// @brief Constructor specifying the BufferWritableView to be used
    ///        for encapsulation.
    ///
    /// Throws exceptions if the BufferWritableView is unsuitable
    /// (empty, too short, etc.).
    GTPv1UEthEncap(const BufferWritableView &buffer)
        : mBufferWritableView(buffer),
          mPayloadArea(buffer.getSub(payload_startOffset)) {
        throwIfBufferIsUnsuitable(
            NETWORKLIB_CURRENT_FUNCTION);
    }

    ///@}

    ///@name Enabling UDP checksum
    ///
    /// UDP checksum is optional on IPv4. Computing it on outgoing
    /// GTPv1-U packets (on UDP) is moderately expensive in terms of
    /// CPU. It is also redundant, as GTPv1-U encapsulates IPv4
    /// traffic which already has its own checksums.
    ///
    /// Therefore, by disabilng it, we can save a bit of CPU time.
    ///
    ///@{

    /// @brief Enable/disable computing UDP checksum (default is
    ///        enabled).
    void enableUDPChecksum(bool enable) { mEnableUDPChecksum = enable; }

    /// @brief Return whether UDP checksum is enabled or not.
    bool enableUDPChecksum(void) { return mEnableUDPChecksum; }

    ///@}

    /// @brief Initialize the encapsulator for a new packet.
    ///
    /// @return A reference to self, so method calls can be chained.
    GTPv1UEthEncap &init() {
        // Initialize the headers in the buffer with the
        // predefined values.
        initHeaders();
        return *this;
    }

    ///@name Ethernet
    ///@{

    /// @brief Set source MAC address.
    /// @return A reference to self, so method calls can be chained.
    GTPv1UEthEncap &setSrcMACAddress(const NetworkLib::MACAddress &src) {
        mBufferWritableView.setMACAddressAt_nocheck(eth_srcAddressOffset, src);
        return *this;
    }

    /// @brief Set destination MAC address.
    /// @return A reference to self, so method calls can be chained.
    GTPv1UEthEncap &setDstMACAddress(const NetworkLib::MACAddress &dst) {
        mBufferWritableView.setMACAddressAt_nocheck(eth_dstAddressOffset, dst);
        return *this;
    }

    ///@}

    ///@name IPv4 Header
    ///@{

    /// @brief Set source IPv4 address.
    /// @return A reference to self, so method calls can be chained.
    GTPv1UEthEncap &setSrcAddress(const NetworkLib::IPv4Address &src) {
        mBufferWritableView.setIPv4AddressAt_nocheck(ipv4_srcAddressOffset,
                                                     src);
        return *this;
    }

    /// @brief Set destination IPv4 address.
    /// @return A reference to self, so method calls can be chained.
    GTPv1UEthEncap &setDstAddress(const NetworkLib::IPv4Address &dst) {
        mBufferWritableView.setIPv4AddressAt_nocheck(ipv4_dstAddressOffset,
                                                     dst);
        return *this;
    }

    /// @brief Set the `Identification` field in the IPv4 header.
    /// @return A reference to self, so method calls can be chained.
    ///
    /// You probably want to use a
    /// 'NetworkLib::IPv4IdentificationSource' to set this value.
    GTPv1UEthEncap &setIdentiifcation(std::uint16_t v) {
        mBufferWritableView.setUint16At_nocheck(ipv4_identificationOffset, v);
        return *this;
    }

    ///@}

    ///@name UDP Header
    ///
    ///@{

    /// @brief Change the source port. Default is 2152 (GTPv1-U).
    /// @return A reference to self, so method calls can be chained.
    GTPv1UEthEncap &setSrcPort(NetworkLib::Port::Number p) {
        mBufferWritableView.setUint16At_nocheck(udp_srcPortOffset, p);
        return *this;
    }

    /// @brief Change the destination port. Default is 2152 (GTPv1-U).
    /// @return A reference to self, so method calls can be chained.
    GTPv1UEthEncap &setDstPort(NetworkLib::Port::Number p) {
        mBufferWritableView.setUint16At_nocheck(udp_dstPortOffset, p);
        return *this;
    }

    ///@}

    ///@name GTPv1-U Header
    ///
    ///@{

    /// @brief Set the TEID of the GTPv1-U tunnel where the packet
    /// will be encapsulated.
    ///
    /// @return A reference to self, so method calls can be chained.
    GTPv1UEthEncap &setTEID(NetworkLib::GTP_TEID::Number t) {
        mBufferWritableView.setUint32At_nocheck(gtp_teidOffset, t);
        return *this;
    }

    ///@}

    ///@name Payload
    ///@{

    /// @brief **Copy** a IPv4 payload in the encapsulation buffer.
    ///
    /// @return A reference to self, so method calls can be chained.
    GTPv1UEthEncap &setPayload(const NetworkLib::BufferView &ipv4Data);

    /// @brief Tells that the payload to be encapsulated is already
    ///        there in the encapsulation buffer given to the
    ///        constructor, starting at offset
    ///        'GTPv1UEthEncap::payload_startOffset'.
    ///
    /// @return A reference to self, so method calls can be chained.
    GTPv1UEthEncap &setPayload();

    ///@name Checksums
    ///@{

    /// @brief Compute and set the checksums according to current data
    ///         in the encapsulation buffer and according to the
    ///         current setting given by 'enableUDPChecksum(bool)'.
    ///
    /// @note Before doing this, ensure you have set:
    ///       1. the IPv4 source and destination addresses;
    ///       2. the IPv4 identification field;
    ///       3. the UDP ports, only if the default 2152 (GTPv1-U) is not ok.
    ///       4. the GTPv1-U payload.
    GTPv1UEthEncap &computeAndSetChecksums();

    ///@}

    ///@name Final result
    ///
    ///@{

    /// @brief Get a BufferWritableView with the encapsulated Ethernet frame.
    const BufferWritableView &getEthFrame() const { return mEthFrame; }

    ///@}
  private:
    enum {
        eth_headerLength = 14,
        ipv4_headerLength = 20,
        udp_headerLength = 8,
        gtp_headerLength = 8,
        totalHeaderLength = eth_headerLength + ipv4_headerLength +
                            udp_headerLength + gtp_headerLength,
        maxPayloadLength =
            65535 - gtp_headerLength - udp_headerLength - ipv4_headerLength,
    };

    // Offsets are relatives to the whole IPv4 packet!
    enum {
        eth_startOffset = 0,

        eth_dstAddressOffset = eth_startOffset,
        eth_srcAddressOffset = eth_startOffset + 6,
        eth_etherTypeOffset = eth_startOffset + 12,

        // Starting offset
        ipv4_startOffset = eth_startOffset + eth_headerLength,

        ipv4_totalLengthOffset = ipv4_startOffset + 2,
        ipv4_identificationOffset = ipv4_startOffset + 4,
        ipv4_checksumOffset = ipv4_startOffset + 10,
        ipv4_srcAddressOffset = ipv4_startOffset + 12,
        ipv4_dstAddressOffset = ipv4_startOffset + 16,

        // 20 bytes for the IPv4 header
        udp_startOffset = ipv4_startOffset + ipv4_headerLength,

        udp_srcPortOffset = udp_startOffset + 0,
        udp_dstPortOffset = udp_startOffset + 2,
        udp_totalLengthOffset = udp_startOffset + 4,
        udp_checksumOffset = udp_startOffset + 6,

        // 8 bytes for the UDP header
        gtp_startOffset = udp_startOffset + udp_headerLength,

        gtp_messageLengthOffset = gtp_startOffset + 2,
        gtp_teidOffset = gtp_startOffset + 4,
    };

    // The whole buffer
    const BufferWritableView mBufferWritableView;

    // The area for the payload
    const BufferWritableView mPayloadArea;

    // The actual length of the payload
    std::size_t mPayloadActualLength;

    // The final Ethernet frame
    BufferWritableView mEthFrame;

    // Flag telling if UDP checksum should be computed or not.
    bool mEnableUDPChecksum = true;

    // Constant raw data for initializing all the IPV4 + UDP + GTPv1-U headers
    static const std::array<unsigned char, totalHeaderLength> headerInitData;

    // Initialize headers with default values.
    void initHeaders() {
        // Note: buffer size has already been checked at this point by
        //       call to throwIfBufferIsUnsuitable()
        unsigned char *p = mBufferWritableView.getUnderlyingWritableBufferPtr();
        std::copy(headerInitData.begin(), headerInitData.end(), p);
    }

    void throwIfBufferIsUnsuitable(const char *method) {
        // Catch some quirks early
        if (mBufferWritableView.size() < totalHeaderLength) {
            std::ostringstream err;
            err << method
                << ": called with "
                   "BufferView.size() == "
                << mBufferWritableView.size() << " (min size is "
                << totalHeaderLength << ')';
            throw std::length_error(err.str());
        }
    }

  public:
    /// @brief When using the no-copy strategy via 'setPayload()' with
    ///        no arguments, this is the offset at which the IPv4
    ///        payload is expected to be in the encapsulation buffer.
    constexpr static const std::size_t payload_startOffset =
        gtp_startOffset + gtp_headerLength;
};

/**
 * @brief A class that encapsulates a IPv4 payload in a IPv4 packet
 *        using GTPv1-U on IPv4.
 */
class GTPv1UIPv4Encap {
  public:
    ///@name Constructors

    /// @brief Constructor specifying the BufferWritableView to be used
    ///        for encapsulation.
    ///
    /// Throws exceptions if the BufferWritableView is unsuitable
    /// (empty, too short, etc.).
    GTPv1UIPv4Encap(const BufferWritableView &buffer)
        : mBufferWritableView(buffer),
          mPayloadArea(buffer.getSub(payload_startOffset)) {
        throwIfBufferIsUnsuitable(
            NETWORKLIB_CURRENT_FUNCTION);
    }

    ///@}

    ///@name Enabling UDP checksum
    ///
    /// UDP checksum is optional on IPv4. Computing it on outgoing
    /// GTPv1-U packets (on UDP) is moderately expensive in terms of
    /// CPU. It is also redundant, as GTPv1-U encapsulates IPv4
    /// traffic which already has its own checksums.
    ///
    /// Therefore, by disabilng it, we can save a bit of CPU time.
    ///
    ///@{

    /// @brief Enable/disable computing UDP checksum (default is
    ///        enabled).
    void enableUDPChecksum(bool enable) { mEnableUDPChecksum = enable; }

    /// @brief Return whether UDP checksum is enabled or not.
    bool enableUDPChecksum(void) { return mEnableUDPChecksum; }

    ///@}

    /// @brief Initialize the encapsulator for a new packet.
    ///
    /// @return A reference to self, so method calls can be chained.
    GTPv1UIPv4Encap &init() {
        // Initialize the headers in the buffer with the
        // predefined values.
        initHeaders();
        return *this;
    }

    ///@name IPv4 Header
    ///@{

    /// @brief Set source IPv4 address.
    /// @return A reference to self, so method calls can be chained.
    GTPv1UIPv4Encap &setSrcAddress(const NetworkLib::IPv4Address &src) {
        mBufferWritableView.setIPv4AddressAt_nocheck(ipv4_srcAddressOffset,
                                                     src);
        return *this;
    }

    /// @brief Set destination IPv4 address.
    /// @return A reference to self, so method calls can be chained.
    GTPv1UIPv4Encap &setDstAddress(const NetworkLib::IPv4Address &dst) {
        mBufferWritableView.setIPv4AddressAt_nocheck(ipv4_dstAddressOffset,
                                                     dst);
        return *this;
    }

    /// @brief Set the `Identification` field in the IPv4 header.
    /// @return A reference to self, so method calls can be chained.
    ///
    /// You probably want to use a
    /// 'NetworkLib::IPv4IdentificationSource' to set this value.
    GTPv1UIPv4Encap &setIdentiifcation(std::uint16_t v) {
        mBufferWritableView.setUint16At_nocheck(ipv4_identificationOffset, v);
        return *this;
    }

    ///@}

    ///@name UDP Header
    ///
    ///@{

    /// @brief Change the source port. Default is 2152 (GTPv1-U).
    /// @return A reference to self, so method calls can be chained.
    GTPv1UIPv4Encap &setSrcPort(NetworkLib::Port::Number p) {
        mBufferWritableView.setUint16At_nocheck(udp_srcPortOffset, p);
        return *this;
    }

    /// @brief Change the destination port. Default is 2152 (GTPv1-U).
    /// @return A reference to self, so method calls can be chained.
    GTPv1UIPv4Encap &setDstPort(NetworkLib::Port::Number p) {
        mBufferWritableView.setUint16At_nocheck(udp_dstPortOffset, p);
        return *this;
    }

    ///@}

    ///@name GTPv1-U Header
    ///
    ///@{

    /// @brief Set the TEID of the GTPv1-U tunnel where the packet
    /// will be encapsulated.
    ///
    /// @return A reference to self, so method calls can be chained.
    GTPv1UIPv4Encap &setTEID(NetworkLib::GTP_TEID::Number t) {
        mBufferWritableView.setUint32At_nocheck(gtp_teidOffset, t);
        return *this;
    }

    ///@}

    ///@name Payload
    ///@{

    /// @brief **Copy** a IPv4 payload in the encapsulation buffer.
    ///
    /// @return A reference to self, so method calls can be chained.
    GTPv1UIPv4Encap &setPayload(const NetworkLib::BufferView &ipv4Data);

    /// @brief Tells that the payload to be encapsulated is already
    ///        there in the encapsulation buffer given to the
    ///        constructor, starting at offset
    ///        'GTPv1UIPv4Encap::payload_startOffset'.
    ///
    /// @return A reference to self, so method calls can be chained.
    GTPv1UIPv4Encap &setPayload();

    ///@name Checksums
    ///@{

    /// @brief Compute and set the checksums according to current data
    ///         in the encapsulation buffer and according to the
    ///         current setting given by 'enableUDPChecksum(bool)'.
    ///
    /// @note Before doing this, ensure you have set:
    ///       1. the IPv4 source and destination addresses;
    ///       2. the IPv4 identification field;
    ///       3. the UDP ports, only if the default 2152 (GTPv1-U) is not ok.
    ///       4. the GTPv1-U payload.
    GTPv1UIPv4Encap &computeAndSetChecksums();

    ///@}

    ///@name Final result
    ///
    ///@{

    /// @brief Get a BufferWritableView with the encapsulated IPv4 packet.
    const BufferWritableView &getIPv4Packet() const { return mIPv4Packet; }

    ///@}
  private:
    enum {
        ipv4_headerLength = 20,
        udp_headerLength = 8,
        gtp_headerLength = 8,
        totalHeaderLength =
            ipv4_headerLength + udp_headerLength + gtp_headerLength,
        maxPayloadLength =
            65535 - gtp_headerLength - udp_headerLength - ipv4_headerLength,
    };

    // Offsets are relatives to the whole IPv4 packet!
    enum {
        // Starting offset
        ipv4_startOffset = 0,

        ipv4_totalLengthOffset = ipv4_startOffset + 2,
        ipv4_identificationOffset = ipv4_startOffset + 4,
        ipv4_checksumOffset = ipv4_startOffset + 10,
        ipv4_srcAddressOffset = ipv4_startOffset + 12,
        ipv4_dstAddressOffset = ipv4_startOffset + 16,

        // 20 bytes for the IPv4 header
        udp_startOffset = ipv4_startOffset + ipv4_headerLength,

        udp_srcPortOffset = udp_startOffset + 0,
        udp_dstPortOffset = udp_startOffset + 2,
        udp_totalLengthOffset = udp_startOffset + 4,
        udp_checksumOffset = udp_startOffset + 6,

        // 8 bytes for the UDP header
        gtp_startOffset = udp_startOffset + udp_headerLength,

        gtp_messageLengthOffset = gtp_startOffset + 2,
        gtp_teidOffset = gtp_startOffset + 4,
    };

    // The whole buffer
    const BufferWritableView mBufferWritableView;

    // The area for the payload
    const BufferWritableView mPayloadArea;

    // The actual length of the payload
    std::size_t mPayloadActualLength;

    // The final IPv4 packet
    BufferWritableView mIPv4Packet;

    // Flag telling if UDP checksum should be computed or not.
    bool mEnableUDPChecksum = true;

    // Constant raw data for initializing all the IPV4 + UDP + GTPv1-U headers
    static const std::array<unsigned char, totalHeaderLength> headerInitData;

    // Initialize headers with default values.
    void initHeaders() {
        // Note: buffer size has already been checked at this point by
        //       call to throwIfBufferIsUnsuitable()
        unsigned char *p = mBufferWritableView.getUnderlyingWritableBufferPtr();
        std::copy(headerInitData.begin(), headerInitData.end(), p);
    }

    void throwIfBufferIsUnsuitable(const char *method) {
        // Catch some quirks early
        if (mBufferWritableView.size() < totalHeaderLength) {
            std::ostringstream err;
            err << method
                << ": called with "
                   "BufferView.size() == "
                << mBufferWritableView.size() << " (min size is "
                << totalHeaderLength << ')';
            throw std::length_error(err.str());
        }
    }

  public:
    /// @brief When using the no-copy strategy via 'setPayload()' with
    ///        no arguments, this is the offset at which the IPv4
    ///        payload is expected to be in the encapsulation buffer.
    constexpr static const std::size_t payload_startOffset =
        gtp_startOffset + gtp_headerLength;
};

} // namespace NetworkLib
} // namespace UPF

#endif
