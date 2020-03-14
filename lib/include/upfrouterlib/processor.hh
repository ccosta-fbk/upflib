#ifndef UPFROUTER_UPFROUTERLIB_PROCESSOR_HH
#define UPFROUTER_UPFROUTERLIB_PROCESSOR_HH

#include <upfnetworklib/networklib.hh>
#include <upfs1aplib/processor.hh>

// For std::vector<T>
#include <vector>

// For std::logic_error
#include <stdexcept>

// Forward declaration of some types in the same way ASN1Lib
// does, so we can freely use pointers or references to it without
// including all C stuff here
extern "C" {
struct S1AP_S1AP_PDU;
typedef S1AP_S1AP_PDU S1AP_S1AP_PDU_t;

struct S1AP_InitialContextSetupResponse;
typedef S1AP_InitialContextSetupResponse S1AP_InitialContextSetupResponse_t;

struct S1AP_InitialContextSetupRequest;
typedef S1AP_InitialContextSetupRequest S1AP_InitialContextSetupRequest_t;
}

namespace UPF {

/// @brief Tools which are quite specific for the Win-Mec project.
namespace UPFRouterLib {
/// @brief Store information on a GTP tunnel.
///
/// A GTP tunnel has two endpoints
struct GTPv1UTunnelInfo {
    /// @brief Standard GTP info identifying the endpoint on the
    ///        eNodeB.
    NetworkLib::GTPv1UEndPoint eNBEndPoint;

    /// @brief Standard GTP info identifying the endpoint on the
    ///        EPC.
    NetworkLib::GTPv1UEndPoint epcEndPoint;
};

/**
 * @brief Specific packet processor for Win-MEC.
 *
 * It specifically intercepts S1AP InitialContextSetupRequest and
 * InitialContextSetupResponse messages, but also decapsulates GTPv1-U
 * traffic.
 *
 * No actual data is processed here: callbacks are provided to do that.
 *
 * @note post-processing of IPv4 SCTP traffic is explicitly disabled,
 *       so SCTP traffic between eNodeBs and EPCs will be forwarded
 *       'as-is'. See also the documentation on
 *       `UPFRouterLib::Router::onIPv4PostProcess()`.
 *
 * Note: being a S1APLib::S1APProcessor, it supports both interface
 *       NetworkLib::EthPacketSink and NetworkLib::IPv4PacketSink,
 *       but the latter has intentionally been disabled.
 *       That is, you should feed this processor only Ethernet data.
 */
class Processor : public S1APLib::S1APProcessor {
  public:
    virtual ~Processor() {}

    /// @brief A struct containing just relevant data of an item in a
    ///        S1AP InitialContextSetupRequest, using common types.
    ///
    /// Note: from 3GPP TS 36.413 v14.4.0 we have the following ASN.1
    /// types
    ///
    /// - MME-UE-S1AP-ID ::= INTEGER (0..4294967295)
    ///
    ///   This is an integer ranging from 0 to (2^32)-1, which fits
    ///   exactly in a std::uint32_t.
    ///
    /// - ENB-UE-S1AP-ID ::= INTEGER (0..16777215)
    ///
    ///   This is an integer ranging from 0 to (2^24)-1. Fits nicely in
    ///   a std::uint32_t
    ///
    /// - E-RAB-ID ::= INTEGER (0..15, ...)
    ///
    ///   This is an integer ranging from 0 to (2^4)-1. Fits nicely in
    ///   a std::uint8_t
    ///
    /// - TransportLayerAddress ::= BIT STRING (SIZE(1..160, ...))
    ///
    ///   At most 160 bits representing an address.  We expect either
    ///   32 for an IPv4 address or 128 for an IPv6 address. We handle
    ///   just IPv4 addresses, therefore we use a
    ///   NetworkLib::IPv4Address
    ///
    struct InitialContextSetupRequestData {
        /// @brief asn1c type: S1AP_MME_UE_S1AP_ID_t
        std::uint32_t mme_ue_s1ap_id;

        /// @brief asn1c type S1AP_ENB_UE_S1AP_ID_t
        std::uint32_t enb_ue_s1ap_id;

        /// @brief  asn1c type S1AP_E_RAB_ID_t
        std::uint8_t e_rab_id;

        /// @brief asn1c type S1AP_TransportLayerAddress_t
        ///
        /// Note: EPC IPv4 address
        NetworkLib::IPv4Address transportLayerAddress;

        /// @brief UE->EPC GTP TEID
        NetworkLib::GTP_TEID::Number gtp_teid;

        /// @brief UE IPv4 address
        NetworkLib::IPv4Address UEIPv4Address;
    };

    /// @brief A group of requests in the same S1AP-PDU message.
    ///
    /// There may be more items in a single request, but in practice,
    /// it's always just one.
    struct InitialContextSetupRequests_t {

        InitialContextSetupRequests_t(Context &ctx) : context(ctx) {}

        /// @brief The context (with decoders).
        Context &context;

        /// @brief The requests.
        std::vector<InitialContextSetupRequestData> requests;
    };

    /// @brief A struct containing just relevant data of an item in a
    ///        S1AP InitialContextSetupResponse, using common types.
    struct InitialContextSetupResponseData {
        /// @brief asn1c type: S1AP_MME_UE_S1AP_ID_t
        std::uint32_t mme_ue_s1ap_id;

        /// @brief asn1c type S1AP_ENB_UE_S1AP_ID_t
        std::uint32_t enb_ue_s1ap_id;

        /// @brief asn1c type S1AP_E_RAB_ID_t
        std::uint8_t e_rab_id;

        /// @brief asn1c type S1AP_TransportLayerAddress_t
        ///
        /// Note: eNB IPv4 address
        NetworkLib::IPv4Address transportLayerAddress;

        /// @brief EPC->UE GTP TEID
        NetworkLib::GTP_TEID::Number gtp_teid;
    };

    /// @brief A group of responses in the same S1AP-PDU message.
    ///
    /// There may be more items in a single responsem but in practice,
    // it's always just one.
    struct InitialContextSetupResponses_t {

        InitialContextSetupResponses_t(Context &ctx) : context(ctx) {}

        /// @brief The context (with decoders).
        Context &context;

        /// @brief The reponses.
        std::vector<InitialContextSetupResponseData> responses;
    };

    ///@name Callbacks
    ///@{

    /// @brief Type of callback called on each S1AP InitialContextSetupRequest
    /// message.
    using InitialContextSetupRequestCbk_t =
        std::function<bool(InitialContextSetupRequests_t &)>;

    /// @brief Set callback to call on each S1AP InitialContextSetupRequest
    /// message.
    void
    onInitialContextSetupRequest(const InitialContextSetupRequestCbk_t &f) {
        mInitialContextSetupRequestCbk = f;
    }

    /// @brief Type of callback called on each S1AP InitialContextSetupResponse
    /// message.
    using InitialContextSetupResponseCbk_t =
        std::function<bool(InitialContextSetupResponses_t &)>;

    /// @brief Set callback to call on each S1AP InitialContextSetupResponse
    /// message.
    void
    onInitialContextSetupResponse(const InitialContextSetupResponseCbk_t &f) {
        mInitialContextSetupResponseCbk = f;
    }

    /// @brief Type of callback called on each GTPv1-U packet.
    using GTPv1UIPv4Cbk_t =
        std::function<bool(NetworkLib::EthPacketProcessor::Context &)>;

    /// @brief Set callback to call on each GTPv1-U packet.
    void onGTPv1U_IPv4(const GTPv1UIPv4Cbk_t &f) { mGTPv1UIPv4Cbk = f; }

    /// @brief Type of callback called on IPv4 post-processing
    using IPv4PostProcessCbk_t =
        std::function<bool(NetworkLib::EthPacketProcessor::Context &)>;

    /// @brief Set callback to call on IPv4 post-processing
    void onIPv4PostProcess(const IPv4PostProcessCbk_t &f) {
        mIPv4PostProcessCbk = f;
    }

    /// @brief Type of callback called on non-IPv4 traffic
    using NonIPv4Cbk_t =
        std::function<bool(NetworkLib::EthPacketProcessor::Context &)>;

    void onNonIPv4(const NonIPv4Cbk_t &f) { mNonIPv4Cbk = f; }

    /// @brief Type of callback called on final processing.
    using FinalProcessCbk_t =
        std::function<bool(NetworkLib::EthPacketProcessor::Context &)>;

    /// @brief Set callback to call on final processing.
    void onFinalProcess(const FinalProcessCbk_t &f) { mFinalProcessCbk = f; }

    ///@}

  protected:
    /// @brief Specialize NetworkLib::EthPacketProcessor::processSCTP()
    virtual bool
    processSCTP(NetworkLib::EthPacketProcessor::Context &context) override {

        // Prevent IPV4 post-processing on all SCTP traffic.
        //
        // This results in not discarding ordinary SCTP traffic
        // because it doesn't come from/isn't directed to a known UE
        // (that's what is done in the IPv4 post-processing phase)
        //
        // This allows SCTP connections being set up (and managed)
        // between eNodeBs and EPCs
        context.postProcessIPv4 = false;
        return true;
    }

    /// @brief Specialize S1APLib::S1APProcessor interface
    virtual bool processS1AP(Context &ctx) override;

    /// @brief Specialize NetworkLib::EthPacketProcessor interface for GTPv1-U
    virtual bool processGTPv1U_IPv4(
        NetworkLib::EthPacketProcessor::Context &context) override {
        if (mGTPv1UIPv4Cbk) {
            return mGTPv1UIPv4Cbk(context);
        }

        return true;
    }

    /// @brief Specialize NetworkLib::EthPacketProcessor::postProcessIPv4()
    virtual bool
    postProcessIPv4(NetworkLib::EthPacketProcessor::Context &context) override {
        if (mIPv4PostProcessCbk) {
            return mIPv4PostProcessCbk(context);
        }

        return true;
    }

    /// @brief Specialize NetworkLib::EthPacketProcessor::processNonIPv4()
    virtual bool
    processNonIPv4(NetworkLib::EthPacketProcessor::Context &context) override {
        if (mNonIPv4Cbk) {
            return mNonIPv4Cbk(context);
        }

        return true;
    }

    /// @brief Specialize NetworkLib::EthPacketProcessor interface for
    //         final processing
    virtual void
    finalProcess(NetworkLib::EthPacketProcessor::Context &context) override {
        if (mFinalProcessCbk) {
            mFinalProcessCbk(context);
        }
    }

    /// @brief Specialize NetworkLib::EthPacketProcessor interface to
    ///        specify that final processing should occur at IPv4
    ///        level (not at L2 level).
    virtual bool finalProcessOnIPv4() override { return true; }

  private:
    // Process a S1AP-PDU (as decoded by ASN1Lib)
    bool processPDU(const S1AP_S1AP_PDU_t &pdu, Context &context);

    // Process a InitialContextSetupRequest (as decoded by ASN1Lib)
    bool processInitialContextSetupRequest(
        const S1AP_InitialContextSetupRequest_t &request, Context &context);

    // Process a InitialContextSetupResponse (as decoded by ASN1Lib)
    bool processInitialContextSetupResponse(
        const S1AP_InitialContextSetupResponse_t &response, Context &context);

    // Callbacks
    InitialContextSetupRequestCbk_t mInitialContextSetupRequestCbk;
    InitialContextSetupResponseCbk_t mInitialContextSetupResponseCbk;
    GTPv1UIPv4Cbk_t mGTPv1UIPv4Cbk;
    FinalProcessCbk_t mFinalProcessCbk;
    IPv4PostProcessCbk_t mIPv4PostProcessCbk;
    NonIPv4Cbk_t mNonIPv4Cbk;
};

} // namespace UPFRouterLib
} // namespace UPF

#endif
