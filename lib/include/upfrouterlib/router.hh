#ifndef UPFROUTER_UPFROUTERLIB_ROUTER_HH
#define UPFROUTER_UPFROUTERLIB_ROUTER_HH

#include <upfnetworklib/networklib.hh>
#include <upfrouterlib/processor.hh>
#include <upfrouterlib/router.hh>

#include <unordered_map>

namespace UPF {
namespace UPFRouterLib {

/**
 * @brief A class implementing most of the Win-Mec functionalities.
 *
 * It is fed:
 *
 * 1. the S1AP traffic between eNodeBs and EPCs, which is then fed to
 *    an instance of UPFRouterLib::Processor to intercept S1AP
 *    InitialContextSetupRequest and InitialContextSetupResponses
 *    messages.
 *
 *    By looking at those messages, this class builds, and keeps
 *    up-to-date, a map (hereby called **UEMap**, see member
 *    ``mUEMap``) of known UEs, mapping an UE IPv4 address to:
 *
 *    * IPv4 address and GTP TEID of a eNodeB endpoint;
 *
 *    * IPv4 address and GTP TEID of a EPC endpoint.
 *
 *    Entries in the map can optionally be modified right before they are
 *    inserted/updated into the map (see ``beforeMapUpsert()``);
 *
 *    Other than that, S1AP traffic is forwarded to its original
 *    destination
 *
 *
 * 2. the GTPv1-U traffic between eNodeBs and EPCs, encpsulating IPv4
 *    traffic between a UE and a EPC.
 *
 *    Provided it comes from a known UE, or is destined to a known UE
 *    (see UEMap above), encapsulated IPv4 traffic is first
 *    decapsulated, then re-encapsulated in an Ethernet frame and sent
 *    either to a specific VNF or to a a default VNF, using an
 *    externally provided map of VNFs (hereby called **VNFMap**).
 *
 * 3. ordinary IPv4 traffic from/to the address of a known UE.
 *
 *    Traffic is encapsulated in GTPv1-U and sent as if it were coming
 *    either from a eNodeB or from a EPC (according to the direction).
 *
 */
class Router : public NetworkLib::IPv4PacketSink {
  public:
    ///@name Constructors
    ///@{

    /// @brief Default constructor
    Router();
    ///@}

    ///@name No copy semantic
    ///@{
    Router(const Router &) = delete;
    Router &operator=(const Router &) = delete;
    ///@}

    ///@name No move semantic
    ///@{
    Router(Router &&) = delete;
    Router &operator=(Router &&) = delete;
    ///@}

    virtual ~Router() {}

    /// @name NetworkLib::IPv4PacketSink interface
    ///@{

    /// @brief Feed IPv4 traffic to this object.
    ///
    /// This is fed with generic IPv4 traffic between the EPC and
    /// the eNB.  S1AP traffic is detected and processed to keep
    /// map ``mUEMap`` up-to-date.
    virtual void
    consumeIPv4Packet(const NetworkLib::BufferView &ipv4data,
                      NetworkLib::ContextUserData &userData =
                          NetworkLib::defaultContextUserData) override {
        mProcessor.consumeIPv4Packet(ipv4data, userData);
    }

    ///@}

    ///@name UEMap
    ///
    /// The UEMap maps an UE's IPv4 address to information on the
    /// endpoints of the GTPv1-U tunnels used to exchange data with
    /// the EPC and vice-versa (via its eNodeB).
    ///
    /// Indirectly, it also tells which UE are currently known
    /// (identified by their IPv4 address).
    ///
    /// The map is populated (and kept up-to-date) by peeking at the
    /// S1AP traffic exchanged beteen eNodeBs and EPCs.
    ///
    ///@{

    ///@brief Type of an entry in the UE map
    using UEMapPair_t = std::pair<NetworkLib::IPv4Address, GTPv1UTunnelInfo>;

    ///@brief Type of the UE map itself
    using UEMap_t =
        std::unordered_map<UEMapPair_t::first_type, UEMapPair_t::second_type>;

    /// @brief Read access to the UE map
    const UEMap_t &getUEMap() const { return mUEMap; }

    /// @brief Read/write access to the UE map
    UEMap_t &getUEMap() { return mUEMap; }

    /// @brief Check if the IPv4 packet bound to the given
    ///        NetworkLib::IPv4Decoder comes from some entry in the UE
    ///        map (non-const version, allowing to change the map
    ///        value through the iterator)
    std::pair<UEMap_t::iterator, bool>
    isIPv4TrafficFromKnownUE(const NetworkLib::IPv4Decoder &ipv4Decoder) {
        UEMap_t::iterator it = mUEMap.find(ipv4Decoder.getSrcAddress());
        return std::make_pair(it, it != mUEMap.end());
    }

    /// @brief Check if the IPv4 packet bound to the given
    ///        NetworkLib::IPv4Decoder comes from some entry in the UE
    ///        map (const version)
    std::pair<UEMap_t::const_iterator, bool>
    isIPv4TrafficFromKnownUE(const NetworkLib::IPv4Decoder &ipv4Decoder) const {
        UEMap_t::const_iterator it = mUEMap.find(ipv4Decoder.getSrcAddress());
        return std::make_pair(it, it != mUEMap.end());
    }

    /// @brief Check if the IPv4 packet bound to the given
    ///        NetworkLib::IPv4Decoder is destined to some entry in
    ///        the UE map (non-const version, allowing to change the map
    ///        value through the iterator)
    std::pair<UEMap_t::iterator, bool>
    isIPv4TrafficToKnownUE(const NetworkLib::IPv4Decoder &ipv4Decoder) {
        UEMap_t::iterator it = mUEMap.find(ipv4Decoder.getDstAddress());
        return std::make_pair(it, it != mUEMap.end());
    }

    /// @brief Check if the IPv4 packet bound to the given
    ///        NetworkLib::IPv4Decoder is destined to some entry in
    ///        the UE map (const version)
    std::pair<UEMap_t::const_iterator, bool>
    isIPv4TrafficToKnownUE(const NetworkLib::IPv4Decoder &ipv4Decoder) const {
        UEMap_t::const_iterator it = mUEMap.find(ipv4Decoder.getDstAddress());
        return std::make_pair(it, it != mUEMap.end());
    }

    bool isIPv4TrafficOfKnownUE(const NetworkLib::BufferView &ipv4Data) const {
        bool found = false;
        UEMap_t::const_iterator dummy;
        NetworkLib::IPv4Decoder ipv4Decoder(ipv4Data);

        std::tie(dummy, found) = isIPv4TrafficFromKnownUE(ipv4Decoder);
        if (!found) {
            std::tie(dummy, found) = isIPv4TrafficToKnownUE(ipv4Decoder);
        }

        return found;
    }

    ///@}

    ///@name Callbacks
    ///@{

    /// @brief Set the callback to call on S1AP traffic
    ///
    /// @return A boolean telling if the (possibly modified) entry
    ///         should be added/updated in the map.
    void onS1APRelevantTraffic(const std::function<void(void)> &f) {
        mOnS1APRelevantTrafficCbk = f;
    }

    /// @brief Set the callback to call when UEMap is about to be
    ///        inserted OR updated (upsert).
    ///
    /// The callback is given a reference to the new entry that's about
    /// to be inserted/updated, so it can be modified at pleasure.
    ///
    /// @return A boolean telling if the (possibly modified) entry
    ///         should be added/updated in the map.
    void beforeUEMapUpsert(const std::function<bool(UEMapPair_t &)> &f) {
        mBeforeUEMapUpsertCbk = f;
    }

    /// @brief Set the callback to call when we intercept GTPv1-U
    ///        traffic.
    ///
    /// Note: it replicates Processor's callback with
    //        the same name.
    void onGTPv1U_IPv4(const Processor::GTPv1UIPv4Cbk_t &f) {
        mProcessor.onGTPv1U_IPv4(f);
    }

    /// @brief Set callback to call on IPv4 post-processing.
    ///
    /// The IPv4 post-processing phase is meant to be used to detect
    /// plain IPv4 traffic from a VNF which should either be
    /// encapsulated in GTPv1-U tunnels or dropped.
    ///
    /// @note It is important to skip this phase for IPv4 traffic
    ///       between eNodeBs and EPCs (like S1AP, or SCTP in general)
    ///       that should be forwarded 'as-is', because it could get
    ///       dropped (ad it is neither destined to, nor coming from,
    ///       a known UE).
    void onIPv4PostProcess(const Processor::IPv4PostProcessCbk_t &f) {
        mProcessor.onIPv4PostProcess(f);
    }

    /// @brief Set callback to call on non-IPv4 traffic (that should
    /// be dropped)
    void onNonIPv4(const Processor::NonIPv4Cbk_t &f) {
        mProcessor.onNonIPv4(f);
    }

    /// @brief Set the callback to call on common network traffic
    /// which shoudl be forwarded "as-is"
    ///
    /// @note Replicates Processor's callback with the
    ///       same name.
    void onFinalProcess(const Processor::FinalProcessCbk_t &f) {
        mProcessor.onFinalProcess(f);
    }

    ///@}

  private:
    using Requests = Processor::InitialContextSetupRequests_t;
    using Request = Processor::InitialContextSetupRequestData;
    using Responses = Processor::InitialContextSetupResponses_t;
    using Response = Processor::InitialContextSetupResponseData;

    // This is the key used to match a InitialContextSetupResponse with
    // its corresponding InitialContextSetupRequest
    struct SetupKey {
        std::uint32_t mme_ue_s1ap_id = 0;
        std::uint32_t enb_ue_s1ap_id = 0;
        std::uint8_t e_rab_id = 0;

        SetupKey() noexcept {};

        friend bool operator==(const SetupKey &a, const SetupKey &b) {
            return a.mme_ue_s1ap_id == b.mme_ue_s1ap_id &&
                   a.enb_ue_s1ap_id == b.enb_ue_s1ap_id &&
                   a.e_rab_id == b.e_rab_id;
        }

        SetupKey(const Request &o) noexcept
            : mme_ue_s1ap_id(o.mme_ue_s1ap_id),
              enb_ue_s1ap_id(o.enb_ue_s1ap_id), e_rab_id(o.e_rab_id) {}

        SetupKey(const Response &o) noexcept
            : mme_ue_s1ap_id(o.mme_ue_s1ap_id),
              enb_ue_s1ap_id(o.enb_ue_s1ap_id), e_rab_id(o.e_rab_id) {}

        /// @brief Function-like object providing a hashing function
        ///        for SetupKey objects (so they can be used in
        ///        collections requiring a hasing function).
        struct Hasher {
            /// @brief Hashing function for unordered collections
            std::size_t operator()(const SetupKey &s) const noexcept {
                const std::size_t h1 =
                    std::hash<std::uint32_t>{}(s.mme_ue_s1ap_id);
                const std::size_t h2 =
                    std::hash<std::uint32_t>{}(s.enb_ue_s1ap_id);
                const std::size_t h3 = std::hash<std::uint8_t>{}(s.e_rab_id);
                return h1 ^ (h2 << 1) ^ (h3 << 2);
            }
        };
    };

    // This is data collected while examinig S1AP
    // InitialContextSetupRequest and InitialContextSetupResponse
    struct SetupData {
        GTPv1UTunnelInfo tunnelInfo;
        NetworkLib::IPv4Address ueAddress;
    };

    bool handleRequests(const Requests &reqs);
    bool handleResponses(const Responses &resps);

    // The processor intercepting traffic
    Processor mProcessor;

    // Maps a request/response to the tunnel info
    //
    std::unordered_map<SetupKey, SetupData, SetupKey::Hasher> mSetupMap;

    // Called on relevant S1AP traffic
    std::function<void(void)> mOnS1APRelevantTrafficCbk;

    // Called before upsert in mUEMap
    std::function<bool(UEMapPair_t &)> mBeforeUEMapUpsertCbk;

    /// @brief The UE -> GTPv1-U tunnel info map computed by this
    /// object.
    ///
    /// Maps the IPv4 address of a UE to the information needed to
    /// encapsulate a IPv4 packet towards the UE (via the eNodeB) or
    /// to the EPC.
    UEMap_t mUEMap;
};

} // namespace UPFRouterLib
} // namespace UPF

#endif
