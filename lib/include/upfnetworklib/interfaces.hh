#ifndef UPFNETWORKLIB_INTERFACES_HH
#define UPFNETWORKLIB_INTERFACES_HH

#include <upfnetworklib/buffers.hh>

namespace UPF {
namespace NetworkLib {

/**
 * @brief User data optionally passed down together with Ethernet
 *        frames or IP packets.
 */
struct ContextUserData {
    void *ptrUserData = nullptr;
    int intUserData = 0;
};

/// @brief Instance for default arguments (for when we don't want to
///        specify any argument)
extern ContextUserData defaultContextUserData;

/**
 * @brief A generic interface for objects consuming IPv4 packets one
 *        at a time, each stored in a BufferView.
 */
class IPv4PacketSink {
  public:
    virtual ~IPv4PacketSink() {}

    /// @brief Write out a IPv4 packet.
    ///
    /// @param ipv4Data A BufferView with the data to be written out.
    ///
    /// @param userData User data. What is done with it depends
    ///        entirely on the implementation (e.g. processors like
    ///        EthPacketProcessor use it to pass down user data to
    ///        callbacks, in its EthPacketProcessor::Context).
    ///
    /// @note It's legit to pass down an empty BufferView: deciding
    ///       what to do with empty packets is up to the
    ///       implmementation to deci
    virtual void
    consumeIPv4Packet(const BufferView &ipv4Data,
                      ContextUserData &userData = defaultContextUserData) = 0;
};

/**
 * @brief A generic interface for objects which are sources of IPv4
 *        packets.
 */
class IPv4PacketSource {
  public:
    virtual ~IPv4PacketSource() {}

    /// @brief True if a packet can be read.
    virtual bool packetAvailable() = 0;

    /// @brief Read in a packet and return a BufferWritableView with
    ///        its data. The given BufferWritableView is used as a
    ///        buffer.
    ///
    /// Return a BufferWritableView which is either empty or is a
    /// (possibly different) view on IPv4 data (i.e. don't assume that
    /// the given BufferWritableView and the returned one are the
    /// same, even if they may have the same underlying PacketBuffer).
    ///
    /// This allows, for example, to read in a whole Ethernet frame
    /// into the given BufferWritableView (or even more than that),
    /// and to return a BufferWritableView containing just the IPv4
    /// payload
    virtual BufferWritableView getIPv4Packet(BufferWritableView &) = 0;
};

/**
 * @brief A generic interface for objects consuming Ethernet frames,
 *        one at a time, each stored in a BufferView.
 */
class EthPacketSink {
  public:
    virtual ~EthPacketSink() {}

    /// @brief Write out a Ethernet frame.
    ///
    /// @param ethData A BufferView with the data to be written out.
    ///
    /// @param userData User data. What is done
    ///        with it depends entirely on the implementation
    ///        (e.g. processors like EthPacketProcessor use it to pass
    ///        down user data to callbacks, in its
    ///        EthPacketProcessor::Context).
    ///
    /// @note It's legit to pass down an empty BufferView: deciding
    ///       what to do with empty packets is up to the
    ///       implementation.
    virtual void
    consumeEthPacket(const BufferView &ethData,
                     ContextUserData &userData = defaultContextUserData) = 0;
};

/**
 * @brief A generic interface for objects which are sources of
 *        Ethernet packets.
 */
class EthPacketSource {
  public:
    virtual ~EthPacketSource() {}

    /// @brief True if a Ethernet frame can be read.
    virtual bool packetAvailable() = 0;

    /// @brief Read in a Ethernet frame and return a
    ///        BufferWritableView with its data. The given
    ///        BufferWritableView is used as a buffer.
    ///
    /// Return a BufferWritableView which is either empty or is a
    /// (possibly different) view on Ethernet data (i.e. don't assume
    /// that the given BufferWritableView and the returned one are the
    /// same, even if they may have the same underlying PacketBuffer).
    virtual BufferWritableView getEthPacket(BufferWritableView &) = 0;
};

} // namespace NetworkLib
} // namespace UPF

#endif
