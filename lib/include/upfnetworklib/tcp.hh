#ifndef UPFNETWORKLIB_TCP_HH
#define UPFNETWORKLIB_TCP_HH

#include <upfnetworklib/buffers.hh>
#include <upfnetworklib/ipv4.hh>
#include <upfnetworklib/utils.hh>

namespace UPF {
namespace NetworkLib {

/**
 * @brief Decode a (whole) UDP packet stored in a BufferView.
 */
class TCPDecoder {
  public:
    ///@name Constructors
    ///@{

    /// @brief Constructor attaching to the given BufferView.
    ///
    /// Throws exceptions if the BufferView is unsuitable (empty, too
    /// short, etc.).
    TCPDecoder(const BufferView &tcpData) : mBufferView(tcpData) {
        throwIfBufferIsUnsuitable(NETWORKLIB_CURRENT_FUNCTION);
    }

    /// @brief Constructor attaching to the given BufferView (moved).
    ///
    /// Throws exceptions if the BufferView is unsuitable (empty, too
    /// short, etc.).
    TCPDecoder(BufferView &&tcpData) : mBufferView{std::move(tcpData)} {
        throwIfBufferIsUnsuitable(NETWORKLIB_CURRENT_FUNCTION);
    }

    ///@}

    ///@name No default constructor
    ///@{
    TCPDecoder() = delete;
    ///@}

    ///@name No copy semantic
    ///@{
    TCPDecoder(const TCPDecoder &) = delete;
    TCPDecoder &operator=(const TCPDecoder &) = delete;
    ///@}

    ///@name No move semantic
    ///@{
    TCPDecoder(TCPDecoder &&) noexcept = delete;
    TCPDecoder &operator=(TCPDecoder &&) = delete;
    ///@}

    ///@name Read access to TCP header fields
    ///@{

    Port::Number getSrcPort() const {
        // Bounds already checked on construction
        return Port::Number(mBufferView.getUint16At_nocheck(srcPortOffset));
    }

    Port::Number getDstPort() const {
        // Bounds already checked on construction
        return Port::Number(mBufferView.getUint16At_nocheck(dstPortOffset));
    }

    std::uint32_t getSequenceNumber() const {
        // Bounds already checked on construction
        return mBufferView.getUint32At_nocheck(sequenceNumberOffset);
    }

    std::uint32_t getAckNumber() const {
        // Bounds already checked on construction
        return mBufferView.getUint32At_nocheck(acknowledgmentNumberOffset);
    }

    std::size_t getDataOffsetBytes() const {
        // Bounds already checked on construction
        return (
            ((mBufferView.getUint16At_nocheck(dataOffsetAndFlagsOffset) >> 12) &
             0x0F) *
            4);
    }

    std::uint16_t getWindowSize() const {
        // Bounds already checked on construction
        return mBufferView.getUint16At_nocheck(windowSizeOffset);
    }

    std::uint16_t getChecksum() const {
        // Bounds already checked on construction
        return mBufferView.getUint16At_nocheck(checksumOffset);
    }

    std::uint16_t getUrgentPointer() const {
        // Bounds already checked on construction
        return mBufferView.getUint16At_nocheck(urgentPointerOffset);
    }

    ///@}

    ///@name Read access to TCP flags
    ///@{

    bool getNSFlag() const {
        // Bounds already checked on construction
        return ((mBufferView.getUint16At_nocheck(dataOffsetAndFlagsOffset) &
                 NS_flagMask) != 0);
    }

    bool getCWRFlag() const {
        // Bounds already checked on construction
        return ((mBufferView.getUint16At_nocheck(dataOffsetAndFlagsOffset) &
                 CWR_flagMask) != 0);
    }

    bool getECEFlag() const {
        // Bounds already checked on construction
        return ((mBufferView.getUint16At_nocheck(dataOffsetAndFlagsOffset) &
                 ECE_flagMask) != 0);
    }

    bool getURGFlag() const {
        // Bounds already checked on construction
        return ((mBufferView.getUint16At_nocheck(dataOffsetAndFlagsOffset) &
                 URG_flagMask) != 0);
    }

    bool getACKFlag() const {
        // Bounds already checked on construction
        return ((mBufferView.getUint16At_nocheck(dataOffsetAndFlagsOffset) &
                 ACK_flagMask) != 0);
    }

    bool getPSHFlag() const {
        // Bounds already checked on construction
        return ((mBufferView.getUint16At_nocheck(dataOffsetAndFlagsOffset) &
                 PSH_flagMask) != 0);
    }

    bool getRSTFlag() const {
        // Bounds already checked on construction
        return ((mBufferView.getUint16At_nocheck(dataOffsetAndFlagsOffset) &
                 RST_flagMask) != 0);
    }

    bool getSYNFlag() const {
        // Bounds already checked on construction
        return ((mBufferView.getUint16At_nocheck(dataOffsetAndFlagsOffset) &
                 SYN_flagMask) != 0);
    }

    bool getFINFlag() const {
        // Bounds already checked on construction
        return ((mBufferView.getUint16At_nocheck(dataOffsetAndFlagsOffset) &
                 FIN_flagMask) != 0);
    }

    ///@}

    ///@name Utilities
    ///@{

    /// @brief Get payload length, in bytes
    std::size_t getDataLengthBytes() const {
        return mBufferView.size() - getDataOffsetBytes();
    }

    /// @brief Return a BufferView with the payload.
    const BufferView getData() const {
        return mBufferView.getSub(getDataOffsetBytes(), getDataLengthBytes());
    }

    ///@}

  private:
    // Constant offsets, in bytes, of header fields
    enum {
        srcPortOffset = 0,
        dstPortOffset = 2,
        sequenceNumberOffset = 4,
        acknowledgmentNumberOffset = 8,
        dataOffsetAndFlagsOffset = 12,
        windowSizeOffset = 14,
        checksumOffset = 16,
        urgentPointerOffset = 18,
        optionsOffset = 20,
    };

    enum FlagMask : std::uint16_t {
        NS_flagMask = 1 << 8,
        CWR_flagMask = 1 << 7,
        ECE_flagMask = 1 << 6,
        URG_flagMask = 1 << 5,
        ACK_flagMask = 1 << 4,
        PSH_flagMask = 1 << 3,
        RST_flagMask = 1 << 2,
        SYN_flagMask = 1 << 1,
        FIN_flagMask = 1,
    };

    // Proper data.
    const BufferView mBufferView;

    void throwIfBufferIsUnsuitable(const char *method) {
        // Catch some quirks early
        if (mBufferView.size() < 20) {
            std::ostringstream err;
            err << method
                << ": called with "
                   "BufferView.size() == "
                << mBufferView.size() << " (min size is 20)";
            throw std::length_error(err.str());
        }
    }
};
} // namespace NetworkLib
} // namespace UPF

#endif
