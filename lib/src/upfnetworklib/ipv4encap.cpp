#include <upfnetworklib/ipv4encap.hh>

namespace UPF {
namespace NetworkLib {

const std::array<unsigned char, IPv4EncapSink::totalHeaderLength>
    IPv4EncapSink::headerInitData{/////////////////////
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
                                  0x08, 0x00};

void IPv4EncapSink::consumeIPv4Packet(const BufferView &ipv4Data,
                                      ContextUserData &userData) {
    // Throw exception if the payload doesn't fit the buffer
    if (ipv4Data.size() > mMaxPayloadLength) {
        std::ostringstream err;
        err << "IPv4EncapSink::consumeIPv4Packet(const BufferView &, "
               "ContextUserData &): "
               "data too large ("
            << "required " << ipv4Data.size() << ", available "
            << mMaxPayloadLength << ')';
        throw std::length_error(err.str());
    }

    // Copy the default Ethernet header
    initHeaders();

    // Set destination and source MAC addresses
    mBufferWritableView.setMACAddressAt_nocheck(eth_dstAddressOffset,
                                                mDefaultDst);
    mBufferWritableView.setMACAddressAt_nocheck(eth_srcAddressOffset,
                                                mDefaultSrc);

    // Copy the payload into the buffer.
    unsigned char *p =
        mBufferWritableView.getUnderlyingWritableBufferPtr() + eth_headerLength;

    ipv4Data.copyTo(0, ipv4Data.size(), p);

    const NetworkLib::BufferWritableView finalEthFrame =
        mBufferWritableView.getSub(0, eth_headerLength + ipv4Data.size());

    // Our Ethernet frame is ready to be sent out via Ethernet.
    mDestination.consumeEthPacket(finalEthFrame, userData);
}

} // namespace NetworkLib
} // namespace UPF
