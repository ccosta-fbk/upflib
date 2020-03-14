#ifndef UPFNETWORKLIB_ETHERNET_HH
#define UPFNETWORKLIB_ETHERNET_HH

// For MACAddress
#include <upfnetworklib/utils.hh>

// For BufferView
#include <upfnetworklib/buffers.hh>

// For EthPacketSink
#include <upfnetworklib/interfaces.hh>

// For std::array<>
#include <array>

// For std::size_t
#include <cstddef>

// For std::uintXX_t
#include <cstdint>

// For iterators (needed?)
#include <iterator>

namespace UPF {
namespace NetworkLib {

/// @brief Namespace for EtherType
namespace EtherType {

/// @brief A specific type to store an EterhType value, with notable
///        values (see also
///        https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml)
enum Type : std::uint16_t {
    IPv4 = 0x0800,
    ARP = 0x0806,
    RARP = 0x8035,
    IPv6 = 0x86dd,
};
} // namespace EtherType

/**
 * @brief Decode an Ethernet frame stored in a BufferView.
 */
class EthFrameDecoder {
  public:
    /// @brief Dump the header of a Ethernet frame in a human-readable way.
    ///
    /// Note: the implementation is in DumperLib.
    friend std::ostream &operator<<(std::ostream &ostr,
                                    const EthFrameDecoder &obj);

    ///@name Constructors

    /// @brief Constructor attaching to the given BufferView.
    ///
    /// Throws exceptions if the BufferView is unsuitable (empty, too
    /// short, etc.).
    EthFrameDecoder(const BufferView &ethdata)
        : mActualEtherType(0), mDataOffset(0), mBufferView(ethdata) {

        throwIfBufferIsUnsuitable(NETWORKLIB_CURRENT_FUNCTION);
        computeDynamicData();
    }

    /// @brief Constructor from the given BufferView (moved).
    ///
    /// Throws exceptions if the BufferView is unsuitable (empty, too
    /// short, etc.).
    EthFrameDecoder(BufferView &&ethdata)
        : mActualEtherType(0), mDataOffset(0), mBufferView(std::move(ethdata)) {
        throwIfBufferIsUnsuitable(NETWORKLIB_CURRENT_FUNCTION);
        computeDynamicData();
    }

    ///@}

    ///@name No default constructor.
    ///@{
    EthFrameDecoder() = delete;
    ///@}

    ///@name No copy semantic
    ///@{
    EthFrameDecoder(const EthFrameDecoder &) = delete;
    EthFrameDecoder &operator=(const EthFrameDecoder &) = delete;
    ///@}

    ///@name No move semantic
    ///@{
    EthFrameDecoder(EthFrameDecoder &&) noexcept = delete;
    EthFrameDecoder &operator=(EthFrameDecoder &&) = delete;
    ///@}

    ///@name Read access to header fields
    ///@{

    /// @brief Get source MAC address
    MACAddress getSrcMACAddress() const {
        // Bounds already checked on construction
        return mBufferView.getMACAddressAt_nocheck(srcMACAddressOffset);
    }

    /// @brief Get destination MAC address
    MACAddress getDstMACAddress() const {
        // Bounds already checked on construction
        return mBufferView.getMACAddressAt_nocheck(dstMACAddressOffset);
    }

    /// @brief Get the actual EtherType (after 802.1Q/802.1ad tags, if any)
    std::uint16_t getEtherType() const {
        // Note: computed by call to computeDynamicData() on
        // construction.
        return mActualEtherType;
    }

    ///@}

    ///@name Utilities
    ///@{

    /// @brief Return `true` if EtherType indicates IPv4 data
    bool isIPv4() const { return (mActualEtherType == EtherType::IPv4); }

    /// @brief Get the original BufferView back.
    ///
    /// That's useful if all you are passed is a EthFrameDecoder
    /// instance, like in the context passed down by
    /// EthPacketProcessor, and you want back the BufferView.
    const BufferView &getEthFrame() const { return mBufferView; }

    /// @brief Get the payload
    BufferView getData() const {
        // see call to computeDynamicData()
        return mBufferView.getSub(getDataOffset(), getDataLengthBytes());
    }

    /// @brief Get the offset of the payload within the BufferView
    std::size_t getDataOffset() const {
        // mDataOffset has been computed before by computeDynamicData()
        return mDataOffset;
    }

    /// @brief Get the payload length
    std::size_t getDataLengthBytes() const {
        return mBufferView.size() - mDataOffset;
    }

    ///@}

  private:
    // Constant offsets, in bytes, of header fields.
    enum {
        dstMACAddressOffset = 0,
        srcMACAddressOffset = 6,
        dynamicHeadersOffset = 12,
    };

    // Dynamically-determined data (cached, thus mutable)
    //
    // Note: mDataOffset == 0 means decoding
    //       was not successful.
    std::uint16_t mActualEtherType;
    unsigned int mDataOffset;

    // Frame raw data + size
    const BufferView mBufferView;

    // Helper methods
    void computeDynamicData();
    void throwIfBufferIsUnsuitable(const char *method) {
        // Catch some quirks early
        if (mBufferView.size() < 14) {
            // The very minimum length of an Ethernet frame is
            // - 6 bytes for dst MAC address
            // - 6 bytes for src MAC address
            // - 2 bytes for EtherType/802.1Q/802.1ad tags)
            std::ostringstream err;
            err << method
                << " called "
                   "with "
                   "BufferView.size() == "
                << mBufferView.size() << " (min size is 14)";
            throw std::runtime_error(err.str());
        }
    }
};

/**
 * @brief Implements a EthPacketSink which makes available the last
 *        consumed Ethernet frame.
 *
 * Note that it is legit to consume an empty Ethernet frame (i.e. an
 * empty BufferView).
 */
class EthPacketTap : public EthPacketSink {
  public:
    virtual ~EthPacketTap() {}

    ///@name Implement EthPacketSink
    ///@{

    virtual void consumeEthPacket(
        const BufferView &ethData,
        ContextUserData &userData = defaultContextUserData) override {
        mEthFrame = ethData;
        mUserData = userData;
    }

    ///@}

    ///@brief Return the last consumed Ethernet frame
    const BufferView &getLastEthFrame() const { return mEthFrame; }

    ///@brief Return the user data of last consumed Ethernet frame.
    ContextUserData getLastUserData() const { return mUserData; }

  private:
    BufferView mEthFrame;
    ContextUserData mUserData;
};

} // namespace NetworkLib
} // namespace UPF

#endif
