#ifndef UPFS1APLIB_PROCESSOR_HH
#define UPFS1APLIB_PROCESSOR_HH

#include <upfnetworklib/networklib.hh>
#include <upfs1aplib/decoders.hh>

namespace UPF {
namespace S1APLib {

/**
 * @brief A generic packet processor which is also aware of S1AP-PDU
 *        messages and can also consume IPv4 data.
 *
 * @note It is a separate class from NetworkLib::EthPacketProcessor
 *       only because we want to publicly expose also the
 *       NetworkLib::IPv4PacketSink interface (which is `protected` in
 *       NetworkLib::EthPacketProcessor).
 */
class S1APProcessor : public NetworkLib::EthPacketProcessor,
                      public NetworkLib::IPv4PacketSink {
  public:
    virtual ~S1APProcessor() {}

    /// @brief Extended context
    ///
    /// It just adds a S1APDecoder, named `s1apDecoder`
    struct Context : public NetworkLib::EthPacketProcessor::Context {
        /// @brief Default constructor
        Context() = default;

        /// @brief Constructor from a a EthPacketProcessor::Context and a
        /// S1APDecoder.
        Context(const NetworkLib::EthPacketProcessor::Context &b,
                const S1APDecoder *p)
            : NetworkLib::EthPacketProcessor::Context(b), s1apDecoder(p) {}

        ///@name Copy semantic
        ///@{
        Context(const Context &) = default;
        Context &operator=(const Context &) = default;
        ///@}

        ///@name Move semantic
        ///@{
        Context(Context &&) = default;
        Context &operator=(Context &&) = default;
        ///@}

        /// @brief S1AP-PDU decoder instance
        const S1APDecoder *s1apDecoder;
    };

    // Note: Interface NetworkLib::EthPacketSink is already implemented by
    //       NetworkLib::EthPacketProcessor

    ///@brief Implement interface NetworkLib::IPv4PacketSink.
    ///
    /// That's useful when processing encapsulated IPv4 traffic.
    virtual void
    consumeIPv4Packet(const NetworkLib::BufferView &ipv4Data,
                      NetworkLib::ContextUserData &userData =
                          NetworkLib::defaultContextUserData) override {
        // Just forward things down
        pushIPv4Packet(ipv4Data, userData);
    }

  protected:
    /// @brief Specializes IPv4PacketProcessor interface
    virtual bool chainOnProcessSCTP_DataChunk(
        NetworkLib::EthPacketProcessor::Context &) override;

    ///@name Processing methods
    ///
    /// Extend the processing methods of EthPacketProcessor.
    ///@{

    /// @brief Interface for processing S1AP messages
    virtual bool processS1AP(Context &) { return true; }

    ///@}
};

} // namespace S1APLib
} // namespace UPF

#endif
