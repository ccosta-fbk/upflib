#ifndef UPFNETWORKLIB_PROCESSOR_HH
#define UPFNETWORKLIB_PROCESSOR_HH

#include <upfnetworklib/buffers.hh>
#include <upfnetworklib/interfaces.hh>
#include <upfnetworklib/utils.hh>

namespace UPF {
namespace NetworkLib {

// Forward declaration of decoders
class EthFrameDecoder;
class IPv4Decoder;
class TCPDecoder;
class UDPDecoder;
class GTPv1UDecoder;
class SCTPDecoder;
class SCTPGenericChunkDecoder;
class SCTPDataChunkDecoder;

/**
 * @brief A generic "processor" of Ethernet packets.
 *
 * By itself it does nothing useful. It is meant to be specialized,
 * overriding the various process*(), chain*() and postProcess*()
 * methods below.
 *
 * Specialization of those methods can access the packet's data
 * via the available decoders referenced in the Context passed
 * down to them.
 */
class EthPacketProcessor : public EthPacketSink {
  public:
    ///@name Destructor
    ///@{
    virtual ~EthPacketProcessor() {}
    ///@}

    /// @brief A context given to each virtual method of
    ///        EthPacketProcessor, providing decoders and other info.
    ///
    /// Packet data should be obtained via the available decoders.
    ///
    /// @note All pointer members would be C++17's `std::optional<T>`
    struct Context {
        ///@name Decoders
        ///@{

        /// @brief Ethernet decoder instance (if any)
        const EthFrameDecoder *ethFrameDecoder = nullptr;

        /// @brief IPv4 decoder instance (if any)
        const IPv4Decoder *ipv4Decoder = nullptr;

        /// @brief TCP decoder instance (if any)
        const TCPDecoder *tcpDecoder = nullptr;

        /// @brief UDP decoder instance (if any)
        const UDPDecoder *udpDecoder = nullptr;

        /// @brief GTPv1-U decoder instance (if any)
        const GTPv1UDecoder *gtpv1uDecoder = nullptr;

        /// @brief SCTP decoder instance (if any)
        const SCTPDecoder *sctpDecoder = nullptr;

        /// @brief SCTP generic chunk decoder instance (if any)
        const SCTPGenericChunkDecoder *sctpGenericChunkDecoder = nullptr;

        /// @brief SCTP DATA chunk decoder instance (if any)
        const SCTPDataChunkDecoder *sctpDataChunkDecoder = nullptr;

        ///@}

        ///@name Postprocessing flags
        ///
        /// Each of these flags control if the postProcess*() method
        /// with the same name gets called.
        ///
        /// @note Currently, we are interested only in postprocessing
        ///       IPv4 traffic, so there's just one flag.
        ///
        ///@{

        /// @brief When `true` an nobody else stopped processing, call
        ///        also 'postProcessIPv4()' on IPv4 data.
        ///
        /// This is meant to be updated (usually to `false`) by
        /// specializations of the processing methods
        bool postProcessIPv4 = true;

        ///@}

        ///@name User data
        ///@{

        /// @brief User data, provided via the EthPacketSink
        ///        interface.
        ///
        /// It's plain old C-style user data to callbacks.  It's up to
        /// specializations of EthPacketProcessor to give it a
        /// meaning, if needed.
        ContextUserData userData;

        /// @}
    };

    /// @name EthPacketSink interface
    ///@{

    /// @brief Feed Ethernet traffic to this processor.
    ///
    /// @param ethData A BufferView with the Ethernet data to be
    ///        processed.
    ///
    /// @param userData This is made available in Context.userData,
    ///        so callbacks may have it.
    virtual void consumeEthPacket(
        const BufferView &ethData,
        ContextUserData &userData = defaultContextUserData) override;

    ///@}

  protected:
    ///@name Processing methods
    ///
    /// Each of these virtual method is passed a Context having only
    /// the available decoders set to a non-NULL value (think of them
    /// as C++17's std::optional<T>)
    ///
    /// The return value tells if we should proceed with
    /// processing (true) or not (false).
    ///
    /// Default implementations do nothing and return true, telling to
    /// proceed and chain.
    ///
    ///@{

    /// @brief Called on Ethernet frames.
    virtual bool processEth(Context &) { return true; }

    /// @brief Called on IPv4 packets.
    virtual bool processIPv4(Context &) { return true; }

    /// @brief Called on TCP packets.
    virtual bool processTCP(Context &) { return true; }

    /// @brief Called on SCTP packets.
    virtual bool processSCTP(Context &) { return true; }

    /// @brief Called once for each SCTP chunk.
    virtual bool processSCTP_GenericChunk(Context &) { return true; }

    /// @brief Called once for each SCTP DATA chunk.
    virtual bool processSCTP_DataChunk(Context &) { return true; }

    /// @brief Called on UDP packets.
    virtual bool processUDP(Context &) { return true; }

    /// @brief Called on GTPv1-U packets.
    virtual bool processGTPv1U(Context &) { return true; }

    /// @brief Called on GTPv1-U packets encapsulating IPv4 traffic.
    virtual bool processGTPv1U_IPv4(Context &) { return true; }

    /// @brief Called on all non-IPv4 traffic
    virtual bool processNonIPv4(Context &) { return true; }

    ///@}

    ///@name Chaining methods
    ///
    /// These virtual methods are for chaining data processing in
    /// generic specializations of this class.
    ///
    /// They are provided so you don't have to remember to call the
    /// corresponding parent method at the end of a specialization.
    ///
    /// The return value tells if we should continue with processing
    /// (true) or not (false).
    ///
    ///@{

    virtual bool chainOnProcessEth(Context &) { return true; }

    virtual bool chainOnProcessIPv4(Context &) { return true; }

    virtual bool chainOnProcessTCP(Context &) { return true; }
    virtual bool chainOnProcessSCTP(Context &) { return true; }
    virtual bool chainOnProcessSCTP_GenericChunk(Context &) { return true; }
    virtual bool chainOnProcessSCTP_DataChunk(Context &) { return true; }

    virtual bool chainOnProcessUDP(Context &) { return true; }
    virtual bool chainOnProcessGTPv1U(Context &) { return true; }

    ///@}

    ///@name Post-processing methods
    ///
    /// Like processing methods, but these are called **after** calling
    /// processing methods and chaining methods.
    ///
    ///@{

    /// @brief called after processing IPv4 data, only if processing
    ///        hasn't been stopped (by returning `false`) and only if
    ///        'Context.postProcessIPv4' is still `true`.
    virtual bool postProcessIPv4(Context &) { return true; }

    ///@}

    /// @brief This is called at the end of all processing only when
    ///        every traversed 'process*()', 'chainOnProcess*()' and
    ///        'postProcess*()' call told us to continue processing.
    virtual void finalProcess(Context &) {}

    /// @brief This is called to know if final processing should be called
    ///        at the Ethernet level (false) or at the IPv4 level (true).
    ///
    ///        Default is to call it at Ethernet
    ///        level. Specializations which are pushing out IPv4
    ///        packets rather than Ethernet frames can override this.
    virtual bool finalProcessOnIPv4() { return false; }

    /// @brief Interface to inject directly IPv4 data in the
    ///        processor.
    ///
    /// This allows specializations of this class to push down also
    /// IPv4 data.  Note that in this case,
    /// 'Context.ethFrameDecoder' will be `nullptr`.
    void pushIPv4Packet(const BufferView &ipv4Data, ContextUserData &userData) {
        Context context;
        context.userData = userData;

        const bool doContinueProcessing = doProcessIPv4(ipv4Data, context);

        if (doContinueProcessing && finalProcessOnIPv4()) {
            finalProcess(context);
        };
    }

  private:
    // Does the actual processing using the given context.
    bool doProcessIPv4(const BufferView &ipv4Data, Context &context);
    bool doProcessSCTP(const BufferView &sctpData, Context &context);
    bool doProcessUDP(const BufferView &udpData, Context &context);
    bool doProcessTCP(const BufferView &tcpData, Context &context);
};

} // namespace NetworkLib
} // namespace UPF

#endif
