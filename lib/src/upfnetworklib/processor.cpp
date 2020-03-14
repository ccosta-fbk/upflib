#include <upfnetworklib/processor.hh>

// Include code for decoders
#include <upfnetworklib/ethernet.hh>
#include <upfnetworklib/gtp_u.hh>
#include <upfnetworklib/ipv4.hh>
#include <upfnetworklib/sctp.hh>
#include <upfnetworklib/tcp.hh>
#include <upfnetworklib/udp.hh>
#include <upfnetworklib/utils.hh>

namespace UPF {
namespace NetworkLib {

void EthPacketProcessor::consumeEthPacket(const BufferView &ethData,
                                          ContextUserData &userData) {
    Context context = {};
    context.userData = userData;
    EthFrameDecoder ethFrameDecoder(ethData);
    context.ethFrameDecoder = &ethFrameDecoder;

    if (processEth(context)) {
        if (chainOnProcessEth(context)) {
            if (ethFrameDecoder.isIPv4()) {
                if (doProcessIPv4(ethFrameDecoder.getData(), context)) {
                    // We arrived at the end with nobody stopping
                    // processing. Do final processing.
                    finalProcess(context);
                }
            } else {
                // Not IPv4, and Eth chaining didn't stop processing?
                //
                // Process non-IPv4 traffic.
                if (processNonIPv4(context)) {
                    // Do final processing.
                    finalProcess(context);
                }
            }
        }
    }
}

bool EthPacketProcessor::doProcessIPv4(const BufferView &ipv4Data,
                                       Context &context) {
    NetworkLib::IPv4Decoder ipv4Decoder(ipv4Data);
    context.ipv4Decoder = &ipv4Decoder;
    auto f = finally([&] { context.ipv4Decoder = nullptr; });

    bool doContinueProcessing = false;

    if (processIPv4(context)) {
        if (chainOnProcessIPv4(context)) {
            if (ipv4Decoder.isUDP()) {

                doContinueProcessing =
                    doProcessUDP(ipv4Decoder.getData(), context);

            } else if (ipv4Decoder.isSCTP()) {

                doContinueProcessing =
                    doProcessSCTP(ipv4Decoder.getData(), context);

            } else if (ipv4Decoder.isTCP()) {

                doContinueProcessing =
                    doProcessTCP(ipv4Decoder.getData(), context);
            } else {
                doContinueProcessing = true;
            }

            if (doContinueProcessing && context.postProcessIPv4) {
                doContinueProcessing = postProcessIPv4(context);
            }
        }
    }

    return doContinueProcessing;
}

bool EthPacketProcessor::doProcessSCTP(const BufferView &sctpData,
                                       Context &context) {
    SCTPDecoder sctpDecoder(sctpData);
    context.sctpDecoder = &sctpDecoder;
    auto f = finally([&] { context.sctpDecoder = nullptr; });

    bool doContinueProcessing = false;

    if (processSCTP(context)) {
        if (chainOnProcessSCTP(context)) {

            // Process SCTP chunks
            for (auto &genericChunk : sctpDecoder.chunks()) {
                context.sctpGenericChunkDecoder = &genericChunk;
                auto f =
                    finally([&] { context.sctpGenericChunkDecoder = nullptr; });

                if (processSCTP_GenericChunk(context)) {
                    if (chainOnProcessSCTP_GenericChunk(context)) {
                        if (genericChunk.isDataChunk()) {
                            NetworkLib::SCTPDataChunkDecoder dataChunkDecoder(
                                genericChunk.getData());

                            context.sctpDataChunkDecoder = &dataChunkDecoder;
                            auto f = finally([&] {
                                context.sctpDataChunkDecoder = nullptr;
                            });

                            if (processSCTP_DataChunk(context)) {
                                if (chainOnProcessSCTP_DataChunk(context)) {
                                    doContinueProcessing = true;
                                }
                            }
                        } else {
                            // Are there non-DATA chunks as well, and
                            // SCTP generic chunk chaining didn't stop
                            // processing? Continue processing to the end.
                            doContinueProcessing = true;
                        }
                    }
                }
            }
        }
    }

    return doContinueProcessing;
}

bool EthPacketProcessor::doProcessUDP(const BufferView &udpData,
                                      Context &context) {
    UDPDecoder udpDecoder(udpData);
    context.udpDecoder = &udpDecoder;
    auto f = finally([&] { context.udpDecoder = nullptr; });

    bool doContinueProcessing = false;

    if (processUDP(context)) {
        if (chainOnProcessUDP(context)) {
            if (udpDecoder.isGTPv1U()) {
                NetworkLib::GTPv1UDecoder gtpv1uDecoder(udpDecoder.getData());
                context.gtpv1uDecoder = &gtpv1uDecoder;
                auto f = finally([&] { context.gtpv1uDecoder = nullptr; });

                if (processGTPv1U(context)) {
                    if (chainOnProcessGTPv1U(context)) {
                        if (gtpv1uDecoder.isIPv4PDU()) {
                            doContinueProcessing = processGTPv1U_IPv4(context);
                        } else {
                            // Not IPv4 traffic and chaining didn't
                            // stop processing? Continue processing to
                            // the end.
                            doContinueProcessing = true;
                        }
                    }
                }
            } else {
                // Not GTPv1-U and UDP chaining didn't stop
                // processing?  Continue processing to the end.
                doContinueProcessing = true;
            }
        }
    }

    return doContinueProcessing;
}

bool EthPacketProcessor::doProcessTCP(const BufferView &tcpData,
                                      Context &context) {
    TCPDecoder tcpDecoder(tcpData);
    context.tcpDecoder = &tcpDecoder;
    auto f = finally([&] { context.tcpDecoder = nullptr; });

    bool doContinueProcessing = false;

    if (processTCP(context)) {
        if (chainOnProcessTCP(context)) {
            doContinueProcessing = true;
        }
    }

    return doContinueProcessing;
}

} // namespace NetworkLib
} // namespace UPF
