#ifndef UPFROUTER_UPFROUTERLIB_GTPENCAPSINK_HH
#define UPFROUTER_UPFROUTERLIB_GTPENCAPSINK_HH

#include <upfnetworklib/networklib.hh>
#include <upfrouterlib/router.hh>

namespace UPF {
namespace UPFRouterLib {

/**
 * @brief A class acting as a IPv4 sink, encapsulating IPV4 traffic in
 *        GTPv1-U and sending it to a IPv4 sink.
 *
 * It uses a UPFRouterLib::Router instance to get the information
 * needed to encapsulate traffic to the correct destination. The
 * traffic is encapsulated using a NetworkLib::GTPv1UEncap.
 *
 * If the IPv4 traffic is to/from an unknown UE, there are two
 * possibilities:
 *
 * 1. if no `onUnknownUE` callback is installed, the offending IPv4
 *    traffic is silently dropped;
 *
 * 2. if a `onUnknownUE` callback is installed, it is given the
 *    offending IPv4 traffic (so it can be logged).
 *
 *    Then, if the callback returns `true`, we send an empty IPv4
 *    frame to the destination (i.e. an empty NetworkLib::BufferView),
 *    so it can be intercepted at a later stage (for example by a
 *    NetworkLib::IPv4PacketTap).
 */
class GTPv1UEncapSink : public NetworkLib::IPv4PacketSink {
  public:
    ///@name Constructors
    ///@{

    /// @brief Constructor.
    ///
    /// @param destination The IPv4acketSink to be used as the
    ///        destination of the encapsulated packets;
    ///
    /// @param bufferWritableView The Bufferwritableview to be used
    ///        to encapsulate IPv4 packets.
    ///
    /// @param router The Router instance to use to get the info
    ///        required to properly encapsulate IPv4 traffic.
    ///
    /// @param identificationSource
    GTPv1UEncapSink(NetworkLib::IPv4PacketSink &destination,
                    NetworkLib::BufferWritableView &bufferWritableView,
                    const Router &router,
                    NetworkLib::IPv4IdentificationSource &identificationSource)
        : mDestination(destination), mRouter(router),
          mIdentificationSource(identificationSource),
          mGTPIPv4Encapper(bufferWritableView) {}

    ///@}

    /// @brief Enable/disable computing UDP checksum
    ///        (default is enabled).
    ///
    /// @see NewtorkLib::
    void enableUDPChecksum(bool enable) {
        mGTPIPv4Encapper.enableUDPChecksum(enable);
    }

    ///@name NetworkLib::IPv4PacketSink interface
    ///@{

    virtual void
    consumeIPv4Packet(const NetworkLib::BufferView &ipv4Data,
                      NetworkLib::ContextUserData &userData =
                          NetworkLib::defaultContextUserData) override {
        const NetworkLib::IPv4Decoder ipv4Decoder(ipv4Data);

        // Alias for the Router map
        const auto &ueMap = mRouter.getUEMap();

        // Look in the map.
        //
        // We assume there's way more traffic **to** a UE than **from** a
        // UE. Therefore, first let's check if this is traffic **to** an
        // UE.
        auto it = ueMap.find(ipv4Decoder.getDstAddress());
        if (it != ueMap.end()) {

            // The packet goes to an UE, thus it goes
            // from a EPC to a eNodeB
            mGTPIPv4Encapper.init()
                .setSrcAddress(it->second.epcEndPoint.ipAddress)
                .setDstAddress(it->second.eNBEndPoint.ipAddress)
                .setTEID(it->second.eNBEndPoint.teid);

            // Save in the user data that this goes to a eNodeB.
            userData.intUserData = 1;

        } else if ((it = ueMap.find(ipv4Decoder.getSrcAddress())) !=
                   ueMap.end()) {

            // The packet comes from an UE, thus it goes
            // from a eNodeB to the EPC
            mGTPIPv4Encapper.init()
                .setSrcAddress(it->second.eNBEndPoint.ipAddress)
                .setDstAddress(it->second.epcEndPoint.ipAddress)
                .setTEID(it->second.epcEndPoint.teid);

            // Save in the user data that this goes to a eNodeB.
            userData.intUserData = 0;
        } else {
            // Unknown... if we have a callback for that, use it.
            if (mUnknownUECbk) {
                if (mUnknownUECbk(ipv4Data)) {

                    // If the callback returns true, send an empty
                    // frame down the destination.
                    NetworkLib::BufferView empty;

                    // Save in the user data that this goes to nowhere.
                    userData.intUserData = 3;

                    mDestination.consumeIPv4Packet(empty, userData);
                }
            }
            return;
        }

        // Set the IPv4 identification field, payload, and compute
        // checksums.
        mGTPIPv4Encapper.setIdentiifcation(mIdentificationSource.get())
            .setPayload(ipv4Data)
            .computeAndSetChecksums();

        // Our IPv4 packet is ready to be sent out.
        mDestination.consumeIPv4Packet(mGTPIPv4Encapper.getIPv4Packet(),
                                       userData);
    }

    ///@}

    ///@name Callbacks
    ///@{

    /// @brief Type of the callback to call when we find IPv4 traffic
    ///        from/to and unknown UE.
    ///
    /// If the function returns true, send an empty BufferView down the sink.
    using UnknownUECbk_t = std::function<bool(const NetworkLib::BufferView &)>;

    /// @brief Set the callback to call when we find IPv4 traffic
    ///        from/to and unknown UE.
    void onUnknownUE(const UnknownUECbk_t &f) { mUnknownUECbk = f; }

    ///@}

  private:
    NetworkLib::IPv4PacketSink &mDestination;
    const Router &mRouter;
    NetworkLib::IPv4IdentificationSource &mIdentificationSource;
    NetworkLib::GTPv1UIPv4Encap mGTPIPv4Encapper;
    UnknownUECbk_t mUnknownUECbk;
};

} // namespace UPFRouterLib
} // namespace UPF

#endif
