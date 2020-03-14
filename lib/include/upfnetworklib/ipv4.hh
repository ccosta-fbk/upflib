#ifndef UPFNETWORKLIB_IPV4_HH
#define UPFNETWORKLIB_IPV4_HH

#include <upfnetworklib/utils.hh>

// For BufferView
#include <upfnetworklib/buffers.hh>

// For IPv4PacketSink
#include <upfnetworklib/interfaces.hh>

// For std::array<>
#include <array>

// For std::list
#include <list>

// For std::size_t
#include <cstddef>

// For std::uintXX_t
#include <cstdint>

// For operator<<() overload
#include <sstream>

namespace UPF {
namespace NetworkLib {

/// @brief A namespace for TCP/UDP/SCTP port numbers.
///
/// While port numbers is a concept that's not related to IPv4 per se
/// (it's rather related to TCP, UDP or SCTP on top of IPv4), their
/// usage in IPv4 is common eough to justify putting them here.
///
/// @note Not using a `enum class` here because we want automatic
///       conversions to/from integers.
///
namespace Port {
/// @brief A type to store a port number, with some well-known port numbers.
enum Number : std::uint16_t {
    Invalid = 0,
    Unspecified = 0,

    GTPv1U = 2152,

    // S1-AP destination SCTP port, from 3GPP TS 36.412 sect. 7
    S1AP = 36412,
};
} // namespace Port

/// @brief A namespace for IPv4 protocol identifiers.
namespace IPv4Protocol {
/// @brief Type storing a protocol identifier, with some well-known values.
enum Type : std::uint8_t {
    NONE = 0,
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    SCTP = 132,
};
} // namespace IPv4Protocol

/**
 * @brief A struct holding the values needed to reassemble fragments
 *        of the same IPv4 packet
 */
class IPv4FragmentKey {
  public:
    ///@name Comparison operators
    ///@{

    /// @brief Equality
    friend bool operator==(const IPv4FragmentKey &lhs,
                           const IPv4FragmentKey &rhs) {
        return (lhs.mIdentification == rhs.mIdentification &&
                (lhs.mProtocol == rhs.mProtocol) &&
                (lhs.mSrcAddress == rhs.mSrcAddress) &&
                (lhs.mDstAddress == rhs.mDstAddress));
    }

    /// @brief Diversity
    friend bool operator!=(const IPv4FragmentKey &lhs,
                           const IPv4FragmentKey &rhs) {
        return !(lhs == rhs);
    }

    ///@}

    ///@name Constructors
    ///@{

    /// @brief Default constructor using an invalid key (to allow usage in
    /// collections)
    IPv4FragmentKey()
        : mSrcAddress{0, 0, 0, 0}, mDstAddress{0, 0, 0, 0},
          mIdentification{0}, mProtocol{IPv4Protocol::NONE} {}

    /// @brief Constructor setting a proper key.
    IPv4FragmentKey(IPv4Protocol::Type protocol, const IPv4Address &src,
                    const IPv4Address &dst, std::uint16_t identification)
        : mSrcAddress(src), mDstAddress(dst), mIdentification(identification),
          mProtocol(protocol) {}

    ///@}

    ///@name Copy semantic
    ///@{
    IPv4FragmentKey(const IPv4FragmentKey &) = default;
    IPv4FragmentKey &operator=(const IPv4FragmentKey &) = default;
    ///@}

    ///@name Move semantic
    ///@{
    IPv4FragmentKey(IPv4FragmentKey &&) noexcept = default;
    IPv4FragmentKey &operator=(IPv4FragmentKey &&) = default;
    ///@}

  private:
    IPv4Address mSrcAddress;
    IPv4Address mDstAddress;
    std::uint16_t mIdentification;
    IPv4Protocol::Type mProtocol;
};

/**
 * @brief A range of values between 0 and 65535/infinity.
 *
 * It's used in reassembling IPv4 fragments.
 */
struct RangeDescriptor {
    ///@name Constants
    ///@{

    /// @brief The constant representing infinity.
    ///
    /// Any value equal or greater than 2^16 should be OK to represent
    /// infinity.
    static const unsigned int infinity = 0x0F0000;

    ///@}

    ///@name Constructors
    ///@{

    /// @brief Default constructor (from 0 to infinity).
    RangeDescriptor() : first(0), last(infinity) {}

    /// @brief Constructor definining a range.
    ///
    /// @param first Start of the range
    ///
    /// @param last End of the range (must be equal or greater than
    ///             ``first``).
    RangeDescriptor(std::size_t first, std::size_t last)
        : first(first), last(last) {}

    ///@}

    /// @brief The start of the range.
    std::size_t first;

    /// @brief The end of the range.
    std::size_t last;
};

/**
 * @brief A simple generator of IPv4 Identification values.
 *
 * That's needed when generating new IPv4 traffic (like, for example,
 * when encapsulating IPv4 in GTPv1-U).
 */
class IPv4IdentificationSource {
  public:
    /// @brief Return a IPv4 identification value
    std::uint16_t get() noexcept { return mIdentification++; }

  private:
    std::uint16_t mIdentification = 0;
};

/**
 * @brief Decode IPv4 packets or fragments stored in a BufferView.
 */
class IPv4Decoder {
  public:
    /// @brief Give a human-readable representation of a IPv4 packet.
    ///
    /// Note: actually implemented in DumperLib.
    friend std::ostream &operator<<(std::ostream &ostr,
                                    const IPv4Decoder &ipv4Decoder);

    ///@name Constructors
    ///@{

    /// @brief Constructor attaching to the given BufferView.
    ///
    /// Throws exceptions if the BufferView is unsuitable (empty, too
    /// short, etc.).
    IPv4Decoder(const BufferView &ipv4data) : mBufferView(ipv4data) {
        throwIfBufferIsUnsuitable(NETWORKLIB_CURRENT_FUNCTION);
    }

    /// @brief Constructor from the given BufferView (moved).
    ///
    /// Throws exceptions if the BufferView is unsuitable (empty, too
    /// short, etc.).
    IPv4Decoder(BufferView &&ipv4data) : mBufferView{std::move(ipv4data)} {
        throwIfBufferIsUnsuitable(NETWORKLIB_CURRENT_FUNCTION);
    }

    ///@}

    ///@name No default constructor
    ///@{
    IPv4Decoder() = delete;
    ///@}

    ///@name No copy semantic
    ///@{
    IPv4Decoder(const IPv4Decoder &) = delete;
    IPv4Decoder &operator=(const IPv4Decoder &) = delete;
    ///@}

    ///@name No move semantic
    ///@{
    IPv4Decoder(IPv4Decoder &&) = delete;
    IPv4Decoder &operator=(IPv4Decoder &&) = delete;
    ///@}

    ///@name Read access to IPv4 header fields
    ///@{

    std::uint8_t getVersion() const {
        // Bounds already checked on construction
        return (mBufferView.getUint8At_nocheck(0) >> 4) & 0x0F;
    }

    std::size_t getHeaderLengthBytes() const {
        // Bounds already checked on construction
        return (mBufferView.getUint8At_nocheck(0) & 0x0F) * 4;
    }

    std::size_t getTotalLengthBytes() const {
        // Bounds already checked on construction
        return mBufferView.getUint16At_nocheck(totalLengthOffset);
    }

    std::uint16_t getIdentification() const {
        // Bounds already checked on construction
        return mBufferView.getUint16At_nocheck(identificationOffset);
    }

    std::uint16_t getFragmentOffsetBytes() const {
        // Bounds already checked on construction
        return (mBufferView.getUint16At_nocheck(fragmentOffsetOffset) &
                0x1FFF) *
               8;
    }

    bool getMoreFragmentsFlag() const {
        // Bounds already checked on construction
        return (mBufferView.getUint16At_nocheck(fragmentOffsetOffset) >> 13) &
               1;
    }

    bool getDontFragmentFlag() const {
        // Bounds already checked on construction
        return (mBufferView.getUint16At_nocheck(fragmentOffsetOffset) >> 14) &
               1;
    }

    unsigned char getTTL() const {
        // Bounds already checked on construction
        return mBufferView.getUint8At_nocheck(ttlOffset);
    }

    IPv4Protocol::Type getProtocol() const {
        // Bounds already checked on construction
        return IPv4Protocol::Type(
            mBufferView.getUint8At_nocheck(protocolOffset));
    }

    /// @brief Get source IPv4 address
    IPv4Address getSrcAddress() const {
        // Bounds already checked on construction
        return mBufferView.getIPv4AddressAt_nocheck(srcAddressOffset);
    }

    /// @brief Get destination IPv4 address
    IPv4Address getDstAddress() const {
        // Bounds already checked on construction
        return mBufferView.getIPv4AddressAt_nocheck(dstAddressOffset);
    }

    ///@}

    ///@name Utilities
    ///@{

    /// @brief Get payload length, in bytes.
    std::size_t getDataLengthBytes() const {
        return getTotalLengthBytes() - getHeaderLengthBytes();
    }

    /// @brief Return a BufferView with the payload.
    BufferView getData() const {
        return mBufferView.getSub(getHeaderLengthBytes(), getDataLengthBytes());
    }

    /// @brief True when this is a UDP packet/fragment.
    bool isUDP() const { return (getProtocol() == IPv4Protocol::UDP); }

    /// @brief True when this is a TCP packet/fragment
    bool isTCP() const { return (getProtocol() == IPv4Protocol::TCP); }

    /// @brief True when this is a SCTP packet/fragment
    bool isSCTP() const { return (getProtocol() == IPv4Protocol::SCTP); }

    ///@}

    /// @brief Get the original BufferView back.
    ///
    /// That's useful if all you are passed is a IPv4Decoder
    /// instance, like in the context passed down by
    /// EthPacketProcessor, and you want back the BufferView.
    const BufferView &getIPv4Packet() const { return mBufferView; }

    ///@name Utilities for packet fragments
    ///@{

    /// @brief True when this is a IPv4 fragment
    bool isAFragment() const {
        return ((getFragmentOffsetBytes() > 0) || getMoreFragmentsFlag());
    }

    /// @brief True when this is the last fragment of a fragmented packet.
    bool isLastFragment() const {
        return ((getFragmentOffsetBytes() > 0) && !(getMoreFragmentsFlag()));
    }

    /// @brief Return the key needed to reassemble fragments of the same packet.
    IPv4FragmentKey getFragmentKey() const {
        return IPv4FragmentKey(getProtocol(), getSrcAddress(), getDstAddress(),
                               getIdentification());
    }

    /// @brief Return the range covered by data in this fragment.
    RangeDescriptor getFragmentRangeDescriptor() const {
        return RangeDescriptor(getFragmentOffsetBytes(),
                               getFragmentOffsetBytes() + getDataLengthBytes());
    }

    ///@}

  private:
    // Constant offsets, in bytes, of header fields
    enum {
        totalLengthOffset = 2,
        identificationOffset = 4,
        fragmentOffsetOffset = 6,
        ttlOffset = 8,
        protocolOffset = 9,
        srcAddressOffset = 12,
        dstAddressOffset = 16,
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

        // Note: same as getVersion()
        if ((mBufferView.getUint8At_nocheck(0) >> 4) != 4) {
            std::ostringstream err;
            err << method << ": not IPV4 header (version is " << +(getVersion())
                << ", should b 4)";
            throw std::runtime_error(err.str());
        }
    }
};

/**
 * @brief Implements a IPv4PacketSink which makes available the last
 *        consumed IPv4 packet.
 *
 * Note that it is legit to consume an empty IPv4 packet (i.e. an
 * empty BufferView).
 */
class IPv4PacketTap : public IPv4PacketSink {
  public:
    virtual ~IPv4PacketTap() {}

    ///@name Implement EthPacketSink
    ///@{

    virtual void consumeIPv4Packet(
        const BufferView &ipv4Data,
        ContextUserData &userData = defaultContextUserData) override {
        mIPv4Packet = ipv4Data;
        mUserData = userData;
    }

    ///@}

    ///@brief Return the last consumed IPv4 packet
    const BufferView &getLastIPv4Packet() const { return mIPv4Packet; }

    ///@brief Return the user data of last consumed IPv4 packet.
    ContextUserData getLastUserData() const { return mUserData; }

  private:
    BufferView mIPv4Packet;
    ContextUserData mUserData;
};

/**
 * @brief Reassembler of IPv4 fragments into packets.
 *
 * A IPv4ReassemblyBuffer should be provided with a BufferWritableView
 * with enough room to reassemble the whole packet, and a IPv4FragmentKey
 * used to check that the fragments actually belong to the packet
 * being reassembled.
 *
 * It is then fed fragments, until the whole packet is reassemled.
 *
 * Instances can be reused to reassemble different packets.
 *
 * @note Incomplete implementation (TODO: copy headers)
 */
class IPv4ReassemblyBuffer {
  public:
    ///@name Constructors

    /// @brief Constructor specifying the reassembling buffer and the
    ///        fragment key common to all fragments.
    IPv4ReassemblyBuffer(const BufferWritableView &buffer,
                         const IPv4FragmentKey &key)
        : mBufferWritableView(buffer), mFragmentKey(key) {
        resetHolesList();
    }

    ///@}

    /// @brief Clears a reassembly buffer, so it can be reused.
    ///
    /// @param key The reassembly key for the new fragment
    void clear(const IPv4FragmentKey &key) {
        mFragmentKey = key;
        resetHolesList();
    }

    /// @brief Add a IPv4 fragment for reassembly.
    ///
    /// When 'check' is true, check if the fragment matches the stored
    /// reassembly key (and throw an exception if it doesn't);
    ///
    /// @return true if the fragment was added.
    bool pushFragment(const BufferView &ipv4data, bool check = true);

    /// @brief Tells if the reassembly is complete.
    bool isComplete() const {
        // As per RFC815, reassembly is complete when
        // the holes list is empty.
        return mHolesList.empty();
    }

  private:
    // The BufferWritableView where reassembly takes place
    const BufferWritableView mBufferWritableView;

    // Key to match fragments
    IPv4FragmentKey mFragmentKey;

    // Hole list to reassemble fragments
    std::list<RangeDescriptor> mHolesList;

    void resetHolesList() {
        mHolesList.clear();
        mHolesList.emplace(mHolesList.begin());
    }
};

} // namespace NetworkLib
} // namespace UPF

#endif
