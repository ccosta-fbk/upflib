#ifndef UPFNETWORKLIB_UDP_HH
#define UPFNETWORKLIB_UDP_HH

#include <upfnetworklib/utils.hh>

// For BufferView
#include <upfnetworklib/buffers.hh>

#include <upfnetworklib/ipv4.hh>

#include <vector>

namespace UPF {
namespace NetworkLib {

/**
 * @brief Decode a (whole) UDP packet stored in a BufferView.
 */
class UDPDecoder {
  public:
    ///@name Constructors
    ///@{

    /// @brief Constructor attaching to the given BufferView.
    ///
    /// Throws exceptions if the BufferView is unsuitable (empty, too
    /// short, etc.).
    UDPDecoder(const BufferView &udpData) : mBufferView(udpData) {
        throwIfBufferIsUnsuitable(NETWORKLIB_CURRENT_FUNCTION);
    }

    /// @brief Constructor attaching to the given BufferView (moved).
    ///
    /// Throws exceptions if the BufferView is unsuitable (empty, too
    /// short, etc.).
    UDPDecoder(BufferView &&udpData) : mBufferView{std::move(udpData)} {
        throwIfBufferIsUnsuitable(NETWORKLIB_CURRENT_FUNCTION);
    }

    ///@}

    ///@name No default constructor
    ///@{
    UDPDecoder() = delete;
    ///@}

    ///@name No copy semantic
    ///@{
    UDPDecoder(const UDPDecoder &) = delete;
    UDPDecoder &operator=(const UDPDecoder &) = delete;
    ///@}

    ///@name No move semantic
    ///@{
    UDPDecoder(UDPDecoder &&) noexcept = delete;
    UDPDecoder &operator=(UDPDecoder &&) = delete;
    ///@}

    ///@name Read access to UDP header fields
    ///@{

    Port::Number getSrcPort() const {
        // Bounds already checked on construction
        return Port::Number(mBufferView.getUint16At_nocheck(srcPortOffset));
    }

    Port::Number getDstPort() const {
        // Bounds already checked on construction
        return Port::Number(mBufferView.getUint16At_nocheck(dstPortOffset));
    }

    std::size_t getTotalLengthBytes() const {
        // Bounds already checked on construction
        return mBufferView.getUint16At_nocheck(totalLengthOffset);
    }

    std::uint16_t getChecksum() const {
        // Bounds already checked on construction
        return mBufferView.getUint16At_nocheck(checksumOffset);
    }

    ///@}

    ///@name Utilities
    ///@{

    /// @brief Get payload length, in bytes
    std::size_t getDataLengthBytes() const {
        return getTotalLengthBytes() - startOfDataOffset;
    }

    /// @brief Return a BufferView with the payload.
    BufferView getData() const {
        return mBufferView.getSub(startOfDataOffset, getDataLengthBytes());
    }

    /// @brief True if this looks like GTPv1-U data.
    ///
    /// We use some heuristic to recognize GTPv1-U:
    ///
    /// * the GTPv1-U header length is 8 bytes, thus the UDP payload
    ///   must be longer than 8 bytes.
    ///
    /// * the most significant 4 bits of the first byte must be 0x30
    ///   (version 1, protocol type 1);
    ///
    /// * the GTPv1-U message length, in bytes, must be equal to the
    ///   UDP payload length + length of GTPv1-U header;
    ///
    /// We currently don't check:
    ///
    /// * destination UDP port: it **should** be port 2152 but we
    ///   don't check that because it could be different;
    ///
    /// * the messageType for a T-PDU: it **should** be is 0xFF, but
    ///   there are other message types, so we don't check that.
    bool isGTPv1U() const {
        const std::size_t udpLen = getDataLengthBytes();
        return ((udpLen > 8) &&
                ((mBufferView.getUint8At_nocheck(startOfDataOffset) & 0xF0) ==
                 0x30) &&
                ((mBufferView.getUint16At_nocheck(startOfDataOffset + 2) +
                  8u) == udpLen));
    }

    ///@}

  private:
    // Constant offsets, in bytes, of header fields
    enum {
        srcPortOffset = 0,
        dstPortOffset = 2,
        totalLengthOffset = 4,
        checksumOffset = 6,
    };

    // Offsets of data fields
    enum {
        startOfDataOffset = 8,
    };

    // Proper data.
    const BufferView mBufferView;

    void throwIfBufferIsUnsuitable(const char *method) {
        // Catch some quirks early
        if (mBufferView.size() < 8) {
            std::ostringstream err;
            err << method
                << ": called with "
                   "BufferView.size() == "
                << mBufferView.size() << " (min size is 8)";
            throw std::length_error(err.str());
        }
    }
};
} // namespace NetworkLib
} // namespace UPF

#endif
