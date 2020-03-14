#include <upfnetworklib/ethernet.hh>

namespace UPF {
namespace NetworkLib {

// Define a constant for Ethernet broadcast address
const MACAddress MACAddress::broadcast(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);

void EthFrameDecoder::computeDynamicData() {
    unsigned int currentOffset = dynamicHeadersOffset;
    std::uint16_t rawType;

    // Note: we already checked that the mBufferView.size() is >= 14
    //       on construction (via call to throwIfBufferIsUnsuitable()),
    //       so there's no underflow risk.
    const std::size_t maxOffset = mBufferView.size() - 2;

    while (currentOffset <= maxOffset) {
        // According to the value, this may be either a size, a type or the
        // beginning of a 802.1Q header or the beginning of a 802.1ad header
        rawType = mBufferView.getUint16At_nocheck(currentOffset);

        if (rawType == 0x88A8 || rawType == 0x8100) {
            // This is actually a 802.1ad tag or a 802.1Q tag. Advance.
            //
            // Note: we could assume that a 802.1Q tag comes after all
            //       the 802.1ad tags.
            currentOffset += 4;
        } else {
            // This is actually an etherType/size. Stop here.
            mActualEtherType = rawType;
            mDataOffset = currentOffset + 2;
            break;
        }
    }

    if (currentOffset > maxOffset) {
        // Throw an exception
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": can't find proper EthType";
        throw std::runtime_error(err.str());
    }
}

} // namespace NetworkLib
} // namespace UPF
