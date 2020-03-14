#ifndef UPFDUMPERLIB_DUMPER_HH
#define UPFDUMPERLIB_DUMPER_HH

#include <upfnetworklib/networklib.hh>
#include <upfs1aplib/s1aplib.hh>
#include <upfrouterlib/upfrouterlib.hh>

// For operator<<() overload
#include <iomanip>
#include <ostream>
#include <sstream>

// For std::string
#include <string>

namespace UPF {

// Dumpers for NetworkLib
namespace NetworkLib {
/// @brief Hex dump of a BufferView
std::ostream &operator<<(std::ostream &ostr, const BufferView &obj);

namespace EtherType {

/// @brief Convert a EtherType to a human-readable string
std::string to_string(Type type);

/// @brief Dump a NetworkLib::EtherType::Type in a human-readable
///        form.
///
/// Note: this is needed because automatic conversions to integer may
///       result in ambiguous calls
inline std::ostream &operator<<(std::ostream &ostr, Type etherType) {
    ostr << to_string(etherType);
    return ostr;
}
} // namespace EtherType

/// @brief Dump a NetworkLib::EthFrameDecoder in a human-readable form.
inline std::ostream &operator<<(std::ostream &ostr, const EthFrameDecoder &d) {
    ostr << "Src MACAddress: " << d.getSrcMACAddress() << '\n'
         << "Dst MACAddress: " << d.getDstMACAddress() << '\n'
         << "     EtherType: " << d.getEtherType() << '\n'
         << "   Data offset: " << d.getDataOffset() << '\n'
         << "     Data size: " << d.getData().size() << '\n';

    return ostr;
}

namespace Port {
/// @brief Dump a NetworkLib::Port::Number in a human-readable form.
///
/// Note: this is needed because automatic conversions to integer may
///       result in ambiguous calls
inline std::ostream &operator<<(std::ostream &ostr, const Number &port) {
    ostr << +(port);
    return ostr;
}
} // namespace Port

namespace IPv4Protocol {
/// @brief Convert a network protocol identifier to a human-readable
///        string.
std::string to_string(const Type &proto);

/// @brief Dump a IPv4Protocol::Type in a human-readable form.
inline std::ostream &operator<<(std::ostream &ostr, const Type &proto) {
    ostr << to_string(proto);
    return ostr;
}
} // namespace IPv4Protocol

// @brief Dump a IPv4Decoder in a human-readable form.
inline std::ostream &operator<<(std::ostream &ostr, const IPv4Decoder &d) {
    ostr << "        Protocol: " << d.getProtocol() << '\n'
         << "Src IPv4 Address: " << d.getSrcAddress() << '\n'
         << "Dst IPv4 Address: " << d.getDstAddress() << '\n'
         << "      Header len: " << d.getHeaderLengthBytes() << '\n'
         << "  Identification: " << asHex16(d.getIdentification()) << '\n'
         << " Fragment Offset: " << d.getFragmentOffsetBytes() << '\n'
         << "  More Fragments: " << d.getMoreFragmentsFlag() << '\n'
         << "  Don't Fragment: " << d.getDontFragmentFlag() << '\n'
         << "    Total length: " << d.getTotalLengthBytes() << '\n'
         << "     Data length: " << d.getDataLengthBytes() << '\n';

    return ostr;
}

/// @brief Dump a UDPDecoder in a human-readable form.
inline std::ostream &operator<<(std::ostream &ostr, const UDPDecoder &d) {
    ostr << "   Src port: " << d.getSrcPort() << '\n'
         << "   Dst port: " << d.getDstPort() << '\n'
         << "   Checksum: " << asHex16(d.getChecksum()) << '\n'
         << "Data length: " << d.getTotalLengthBytes() << '\n';

    return ostr;
}

/// @brief Dump a TCPDecoder in a human-readable form.
inline std::ostream &operator<<(std::ostream &ostr, const TCPDecoder &d) {
    ostr << "       Src port: " << d.getSrcPort() << '\n'
         << "       Dst port: " << d.getDstPort() << '\n'
         << "Sequence number: " << d.getSequenceNumber() << '\n'
         << "     Ack number: " << d.getAckNumber() << '\n'
         << "    Data offset: " << d.getDataOffsetBytes() << '\n'
         << "          Flags: NS:" << d.getNSFlag() << " CWR:" << d.getCWRFlag()
         << " ECE:" << d.getECEFlag() << " URG:" << d.getURGFlag()
         << " ACK:" << d.getACKFlag() << " PSH:" << d.getPSHFlag()
         << " RST:" << d.getRSTFlag() << " SYN:" << d.getSYNFlag()
         << " FIN:" << d.getFINFlag() << '\n'
         << "    Window size: " << d.getWindowSize() << '\n'
         << "       Checksum: " << asHex16(d.getChecksum()) << '\n'
         << " Urgent pointer: " << d.getUrgentPointer() << '\n'
         << "    Data length: " << d.getDataLengthBytes() << '\n';

    return ostr;
}

namespace SCTPChunk {

/// @brief Convert a SCTP chunk type identifier to a human-readable
///        string
std::string to_string(const SCTPChunk::Type &type);
} // namespace SCTPChunk

/// @brief Dump a SCTPGenericChunkDecoder in a human-readable form.
inline std::ostream &operator<<(std::ostream &ostr,
                                const SCTPGenericChunkDecoder &d) {
    ostr << "  Chunk Type: " << SCTPChunk::to_string(d.getType()) << '\n'
         << "       Flags: " << asHex16(d.getFlags()) << '\n'
         << " Data length: " << d.getTotalLengthBytes() << '\n';
    return ostr;
}

/// @brief Dump a SCTPDataChunkDecoder content in a human-readable form.
inline std::ostream &operator<<(std::ostream &ostr,
                                const SCTPDataChunkDecoder &d) {
    ostr << "       Chunk type: " << SCTPChunk::to_string(d.getType()) << '\n'
         << "            Flags: I:" << d.getFlagI() << " U:" << d.getFlagU()
         << " B:" << d.getFlagB() << " E:" << d.getFlagE() << '\n'
         << "              TSN: " << asHex32(d.getTSN()) << '\n'
         << "Stream identifier: " << asHex16(d.getStreamIdentifier()) << '\n'
         << "Stream seq number: " << asHex16(d.getStreamSequenceNumber())
         << '\n'
         << " Payload proto id: " << asHex32(d.getPayloadProtocolIdentifier())
         << '\n'
         << "      IsAFragment: " << d.isAFragment() << '\n'
         << "      Data length: " << d.getDataLengthBytes() << '\n';

    return ostr;
}

/// @brief Dump a SCTPDecoder content in a human-readable form
inline std::ostream &operator<<(std::ostream &ostr, const SCTPDecoder &d) {
    ostr << "        Src port: " << d.getSrcPort() << '\n'
         << "        Dst port: " << d.getDstPort() << '\n'
         << "Verification tag: " << d.getVerificationTag() << '\n'
         << "        Checksum: " << asHex16(d.getChecksum()) << '\n'
         << "          Chunks: " << d.chunks().size() << '\n';

    return ostr;
}

namespace GTP_TEID {

/// @brief Dump a GTP_TEID::Number in a human-readable form.
inline std::ostream &operator<<(std::ostream &ostr, const Number &d) {
    ostr << asHex32(d);
    return ostr;
}
} // namespace GTP_TEID

/// @brief Dump a GTPv1UEndPoint in a human-readable form.
inline std::ostream &operator<<(std::ostream &ostr, const GTPv1UEndPoint &d) {
    ostr << d.ipAddress;
    if (d.port != 0) {
        // Omit port if unspecified
        ostr << ':' << d.port;
    }
    ostr << "@teid(" << d.teid << ')';

    return ostr;
}

/// @brief Dump a GTPv1UDecoder in a human-readable form.
inline std::ostream &operator<<(std::ostream &ostr, const GTPv1UDecoder &d) {
    ostr << "        Version: " << +(d.getVersion()) << '\n'
         << "  Protocol type: " << +(d.getProtocolType()) << '\n'
         << "          Flags: E:" << d.hasNextExtensionField()
         << " S:" << d.hasSequenceNumberField() << " PN:" << d.hasNPDUField()
         << '\n'
         << "   Message type: " << +(d.getMessageType()) << '\n'
         << " Message length: " << +(d.getMessageLength()) << '\n'
         << "           TEID: " << d.getTEID() << '\n'
         << "Sequence number: "
         << (d.hasSequenceNumberField() ? asHex16(d.getSequenceNumber())
                                        : "none")
         << '\n'
         << "           NPDU: "
         << (d.hasNPDUField() ? asHex16(d.getNPDUNumber()) : "none") << '\n'
         << " N ext. headers: " << d.getExtensionHeaders().size() << '\n';

    return ostr;
}

/// @brief Dump the content of a Pcap global header in a
///        human-readable form.
std::ostream &operator<<(std::ostream &ostr, const PcapHeader &header);

/// @brief Dump the content of a Pcap record header in a
///        human-readable form.
std::ostream &operator<<(std::ostream &ostr, const PcapRecord::Header &header);

/// @brief Dump the content of a Linux cooked header in a
///        human-readable form.
std::ostream &operator<<(std::ostream &ostr,
                         const PcapRecord::LinuxCooked &header);

} // namespace NetworkLib

namespace S1APLib {
/// @brief Dump a S1APDecoder in a human-readable form.
std::ostream &operator<<(std::ostream &ostr, const S1APDecoder &d);

/// @brief Dump a S1APProcessor::Context in a human-readable form.
inline std::ostream &operator<<(std::ostream &ostr,
                                const S1APProcessor::Context &c) {
    ostr << "      Src Eth Address: ";
    if (c.ethFrameDecoder) {
        ostr << c.ethFrameDecoder->getSrcMACAddress() << '\n';
    } else {
        ostr << "N/A\n";
    }

    ostr << "     Src IPv4 Address: ";
    if (c.ipv4Decoder) {
        ostr << c.ipv4Decoder->getSrcAddress() << '\n';
    } else {
        ostr << "N/A\n";
    }

    ostr << "             Src port: ";
    if (c.sctpDecoder) {
        ostr << c.sctpDecoder->getSrcPort();
    } else {
        ostr << "N/A\n";
    }

    ostr << "      Dst Eth Address: ";
    if (c.ethFrameDecoder) {
        ostr << c.ethFrameDecoder->getDstMACAddress() << '\n';
    } else {
        ostr << "N/A\n";
    }

    ostr << "     Dst IPv4 Address: ";
    if (c.ipv4Decoder) {
        ostr << c.ipv4Decoder->getDstAddress() << '\n';
    } else {
        ostr << "N/A\n";
    }

    ostr << "             Dst port: ";
    if (c.sctpDecoder) {
        ostr << c.sctpDecoder->getDstPort() << '\n';
    } else {
        ostr << "N/A\n";
    }

    return ostr;
}

} // namespace S1APLib

namespace UPFRouterLib {
/// @brief Dump a GTPv1UTunnelInfo in a human-readable form.
///
/// Note: in diagrams, the eNodeBs are usually on the left, while the
///       EPCs are on the right. We do the same.
inline std::ostream &operator<<(std::ostream &ostr, const GTPv1UTunnelInfo &d) {
    ostr << d.eNBEndPoint << " <-> " << d.epcEndPoint;
    return ostr;
}

/// @brief Dump a UPFRouterLib::Processor::InitialContextSetupRequestData in a
///        human-readable form.
inline std::ostream &
operator<<(std::ostream &ostr,
           const Processor::InitialContextSetupRequestData &d) {
    ostr << "       MME_UE_S1AP_ID: " << d.mme_ue_s1ap_id << '\n'
         << "       ENB_UE_S1AP_ID: " << d.enb_ue_s1ap_id << '\n'
         << "             E_RAB_ID: " << +(d.e_rab_id) << '\n'
         << "transportLayerAddress: " << d.transportLayerAddress << '\n'
         << "             GTP_TEID: " << d.gtp_teid << '\n'
         << "      UE IPv4 Address: " << d.UEIPv4Address << '\n';

    return ostr;
}

/// @brief Dump a UPFRouterLib::Processor::InitialContextSetupRequests_t in a
///        human-readable form.
inline std::ostream &
operator<<(std::ostream &ostr,
           const Processor::InitialContextSetupRequests_t &d) {
    ostr << d.context;
    for (const auto &i : d.requests) {
        ostr << "---\n" << i;
    }

    return ostr;
}

/// @brief Dump a UPFRouterLib::Processor::InitialContextSetupResponseData in
///        a human-readable form.
inline std::ostream &
operator<<(std::ostream &ostr,
           const Processor::InitialContextSetupResponseData &d) {

    ostr << "       MME_UE_S1AP_ID: " << d.mme_ue_s1ap_id << '\n'
         << "       ENB_UE_S1AP_ID: " << d.enb_ue_s1ap_id << '\n'
         << "             E_RAB_ID: " << +(d.e_rab_id) << '\n'
         << "transportLayerAddress: " << d.transportLayerAddress << '\n'
         << "             GTP_TEID: " << d.gtp_teid << '\n';

    return ostr;
}

/// @brief Dump a UPFRouterLib::Processor::InitialContextSetupReponses_t in a
///        human-readable form.
inline std::ostream &
operator<<(std::ostream &ostr,
           const Processor::InitialContextSetupResponses_t &d) {
    ostr << d.context;
    for (const auto &i : d.responses) {
        ostr << "---\n" << i;
    }

    return ostr;
}

/// @brief Dump a UPFRouterLib::MatchingRule in a human-readable form.
inline std::ostream &operator<<(std::ostream &ostr,
                                const UPFRouterLib::MatchingRule &d) {
    ostr << +(d.protocol) << '-' << d.dstCidr << '-' << d.dstPort;
    return ostr;
}

} // namespace UPFRouterLib

/// @brief Cross-platform code dumping most types in a human-readable
///        form.
namespace DumperLib {

/**
 * @brief Dumper of a Ethernet frame.
 */
class EthDumper {
  public:
    friend std::ostream &operator<<(std::ostream &ostr, const EthDumper &eth);

    ///@name Constructors
    ///@{

    /// @brief Constructor specifying the BufferView where the
    ///        Ethernet data to be dumped is stored.
    EthDumper(const NetworkLib::BufferView &ethData) : mBufferView(ethData) {}

    ///@}

  private:
    const NetworkLib::BufferView mBufferView;
};

/**
 * @brief Dumper of a IPv4 packet.
 */
class IPv4Dumper {
  public:
    friend std::ostream &operator<<(std::ostream &ostr, const IPv4Dumper &ipv4);

    ///@name Constructors
    ///@{

    /// @brief Constructor specifying the BufferView where the IPv4
    ///        data to be dumped is stored.
    IPv4Dumper(const NetworkLib::BufferView &ipv4Data)
        : mBufferView(ipv4Data) {}

    ///@}

  private:
    const NetworkLib::BufferView mBufferView;
};

/**
 * @brief A IPv4DumperProcessor implements the actual logic of dumping
 *        a packet
 */
class IPv4DumperProcessor : public S1APLib::S1APProcessor {
  public:
    ///@name Constructors
    ///@{

    /// @brief Constructor specifying the ostream where data should be
    ///        dumped.
    IPv4DumperProcessor(std::ostream &ostr) : mOstr{ostr} {}

    ///@}

  private:
    std::ostream &mOstr;

  protected:
    ///@name Specialize NetworkLib::EthPacketProcessor interface
    ///@{

    virtual bool
    processIPv4(NetworkLib::EthPacketProcessor::Context &ctx) override {
        if (ctx.ipv4Decoder) {
            mOstr << "+IPv4\n" << *ctx.ipv4Decoder << '\n';
        }
        return true;
    }

    virtual bool
    processTCP(NetworkLib::EthPacketProcessor::Context &ctx) override {
        if (ctx.tcpDecoder) {
            mOstr << *ctx.tcpDecoder << '\n';
        }
        return true;
    }

    virtual bool
    processSCTP(NetworkLib::EthPacketProcessor::Context &ctx) override {
        if (ctx.sctpDecoder) {
            mOstr << "+ SCTP\n" << *ctx.sctpDecoder << '\n';
        }
        return true;
    }

    virtual bool processSCTP_GenericChunk(
        NetworkLib::EthPacketProcessor::Context &ctx) override {

        if (ctx.sctpGenericChunkDecoder) {
            const bool isDataChunk = ctx.sctpGenericChunkDecoder->getType() ==
                                     NetworkLib::SCTPChunk::DATA;

            if (!isDataChunk) {
                mOstr << "+ SCTP Chunk\n"
                      << *ctx.sctpGenericChunkDecoder << '\n';
            }
        }

        return true;
    }

    virtual bool processSCTP_DataChunk(
        NetworkLib::EthPacketProcessor::Context &ctx) override {
        if (ctx.sctpDataChunkDecoder) {
            mOstr << "+ SCTP Data Chunk\n" << *ctx.sctpDataChunkDecoder << '\n';
        }
        return true;
    }

    virtual bool
    processUDP(NetworkLib::EthPacketProcessor::Context &ctx) override {
        if (ctx.udpDecoder) {
            mOstr << "+ UDP\n" << *ctx.udpDecoder << '\n';
        }
        return true;
    }

    virtual bool
    processGTPv1U(NetworkLib::EthPacketProcessor::Context &ctx) override {
        if (ctx.gtpv1uDecoder) {
            mOstr << "+ GTPv1-U\n" << *ctx.gtpv1uDecoder << '\n';
        }
        return true;
    }

    virtual bool
    processGTPv1U_IPv4(NetworkLib::EthPacketProcessor::Context &ctx) override {
        if (ctx.gtpv1uDecoder) {
            mOstr << "+ Encap Ipv4\n";
            IPv4DumperProcessor nestedDumper(mOstr);
            nestedDumper.consumeIPv4Packet(ctx.gtpv1uDecoder->getData(),
                                           ctx.userData);
        }

        // Don't recurse further, as we are doing it.
        return false;
    }

    // Override S1APLib::S1APProcessor interface
    virtual bool processS1AP(Context &ctx) override {
        if (ctx.s1apDecoder) {
            mOstr << "+ S1AP-PDU\n" << *ctx.s1apDecoder << '\n';
        }
        return true;
    }

    ///@}
};

/// @brief Dump a IPv4 dumper in a human-readable form.
std::ostream &operator<<(std::ostream &ostr, const IPv4Dumper &ipv4);

} // namespace DumperLib
} // namespace UPF

#endif
