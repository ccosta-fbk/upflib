#ifndef UPFNETWORKLIB_IPV4_ENCAP_HH
#define UPFNETWORKLIB_IPV4_ENCAP_HH

#include <upfnetworklib/buffers.hh>
#include <upfnetworklib/interfaces.hh>
#include <upfnetworklib/ipv4.hh>

namespace UPF {
namespace NetworkLib {

/**
 * @brief A class acting as a IPv4 sink, encapsulating IPV4 traffic in
 *        a Ethernet frame and sending it to a Ethernet sink.
 */
class IPv4EncapSink : public NetworkLib::IPv4PacketSink {
  public:
    ///@name Constructors
    ///@{

    /// @brief Constructor.
    ///
    /// @param destination The EthPacketSink to be used as the
    ///        destination of the encapsulated packets;
    ///
    /// @param bufferWritableView The Bufferwritableview to be used
    ///        to encapsulate IPv4 packets.
    IPv4EncapSink(EthPacketSink &destination,
                  BufferWritableView &bufferWritableView)
        : mDestination(destination), mBufferWritableView(bufferWritableView),

          // Note: if size is less than eth_headerLength, we throw.
          mMaxPayloadLength{mBufferWritableView.size() - eth_headerLength} {
        throwIfBufferIsUnsuitable("IPv4EncapSink::IPv4EncapSink(EthPacketSink "
                                  "&, BufferWritableView &)");
    }

    ///@}

    ///@name NetworkLib::IPv4PacketSink interface
    ///@{

    virtual void consumeIPv4Packet(
        const NetworkLib::BufferView &ipv4Data,
        ContextUserData &userData = defaultContextUserData) override;

    ///@}

    ///@name Default MAC addresses
    ///@{

    /// @brief Set the fake source MAC address to be used when
    ///        consuming IPV4 packets.
    ///
    /// The default value is 00:00:00:00:00:00
    void setDefaultSrcAddress(const MACAddress &a) { mDefaultSrc = a; }

    /// @brief Set the fake destination MAC address to be used when
    ///        consuming IPV4 packets.
    ///
    /// The default value is 00:00:00:00:00:00
    void setDefaultDstAddress(const MACAddress &a) { mDefaultDst = a; }

    ///@}

  private:
    enum {
        eth_headerLength = 14,
        totalHeaderLength = eth_headerLength,
    };

    // Offsets are relatives to the whole packet!
    enum {
        eth_startOffset = 0,

        eth_dstAddressOffset = eth_startOffset,
        eth_srcAddressOffset = eth_startOffset + 6,
        eth_etherTypeOffset = eth_startOffset + 12,
    };

    NetworkLib::EthPacketSink &mDestination;
    NetworkLib::BufferWritableView &mBufferWritableView;

    const std::size_t mMaxPayloadLength;

    MACAddress mDefaultSrc{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    MACAddress mDefaultDst{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // Constant raw data for initializing all the Ethernet header
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
};

} // namespace NetworkLib
} // namespace UPF

#endif
