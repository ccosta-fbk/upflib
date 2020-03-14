#include <upfdumperlib/dumper.hh>

#include <upfnetworklib/gtp_u.hh>
#include <upfnetworklib/sctp.hh>
#include <upfnetworklib/tcp.hh>
#include <upfnetworklib/udp.hh>
#include <upfs1aplib/s1aplib.hh>

// For std::hex and such
#include <iomanip>

// For std::ostringstream
#include <sstream>

namespace UPF {
namespace NetworkLib {

std::ostream &operator<<(std::ostream &ostr, const BufferView &obj) {

    auto guard = Iosguard(ostr);
    const int dumpedBytesPerLine = 32;

    std::string dumpedChars;

    // Round up to next greater multiple;
    auto actualSize = obj.mSize;
    if ((actualSize % dumpedBytesPerLine) != 0) {
        actualSize =
            (((obj.mSize / dumpedBytesPerLine) + 1) * dumpedBytesPerLine);
    }

    ostr << std::setfill('0') << std::hex;

    for (std::size_t i = 0; i < actualSize; ++i) {

        if ((i % dumpedBytesPerLine) == 0) {
            if (i > 0) {
                ostr << '|' << dumpedChars << "|\n";
                dumpedChars.clear();
            }

            ostr << std::setw(4) << i << ": ";
        }

        if (i < obj.mSize) {
            ostr << std::setw(2) << +(obj.mPtr[i]) << ' ';

            if (std::isprint(static_cast<unsigned char>(obj.mPtr[i]))) {
                dumpedChars += static_cast<char>(obj.mPtr[i]);
            } else {
                dumpedChars += '.';
            }

        } else {
            // Advance 3 chars
            ostr << "-- ";
            dumpedChars += '.';
        }
    }

    ostr << '|' << dumpedChars << "|\n";
    dumpedChars.clear();

    return ostr;
}

namespace EtherType {
std::string to_string(Type type) {
    using namespace std::string_literals;
    std::string result;

    switch (type) {
    case IPv4:
        result = "IPv4"s;
        break;

    case ARP:
        result = "ARP"s;
        break;

    case RARP:
        result = "RARP"s;
        break;

    case IPv6:
        result = "IPv6"s;
        break;

    default: {
        std::ostringstream o;
        o << '(' << asHex16(type) << ')';
        result = o.str();
        break;
    }
    }

    return result;
}

} // namespace EtherType

namespace IPv4Protocol {
std::string to_string(const Type &proto) {
    using namespace std::string_literals;

    std::string result;

    switch (proto) {
    case ICMP:
        result = "ICMP"s;
        break;

    case IGMP:
        result = "IGMP"s;
        break;

    case TCP:
        result = "TCP"s;
        break;

    case UDP:
        result = "UDP"s;
        break;

    case SCTP:
        result = "SCTP"s;
        break;

    default: {
        std::ostringstream o;
        o << '(' << asHex16(proto) << ')';
        result = o.str();
        break;
    }
    }

    return result;
}
} // namespace IPv4Protocol

namespace SCTPChunk {
// Convert a chunk type identifier to a human-readable string
std::string to_string(const SCTPChunk::Type &type) {
    std::string result;

    switch (type) {

#define CASE(T)                                                                \
    case SCTPChunk::T:                                                         \
        result = #T;                                                           \
        break

        CASE(DATA);
        CASE(INIT);
        CASE(INIT_ACK);
        CASE(SACK);
        CASE(HEARTBEAT);
        CASE(HEARTBEAT_ACK);
        CASE(ABORT);
        CASE(SHUTDOWN);
        CASE(SHUTDOWN_ACK);
        CASE(ERROR);
        CASE(COOKIE_ECHO);
        CASE(COOKIE_ACK);
        CASE(ECNE);
        CASE(CWR);
        CASE(SHUTDOWN_COMPLETE);
        CASE(AUTH);
        CASE(I_DATA);
        CASE(ASCONF_ACK);
        CASE(RE_CONFIG);
        CASE(PAD);
        CASE(FORWARD_TSN);
        CASE(ASCONF);
        CASE(I_FORWARD_TSN);
#undef CASE

    default: {
        std::ostringstream o;
        o << asHex8(type) << ')';
        result = o.str();
        break;
    }
    }

    return result;
}

} // namespace SCTPChunk

std::ostream &operator<<(std::ostream &ostr,
                         const PcapRecord::LinuxCooked &header) {

    ostr << "   packet_type: " << header.packet_type;

    switch (header.packet_type) {
    case 0:
        ostr << " (from others to us)\n";
        break;

    case 1:
        ostr << " (broadcasted by others)\n";
        break;

    case 2:
        ostr << " (multicasted by others)\n";
        break;

    case 3:
        ostr << " (from others to others)\n";
        break;

    case 4:
        ostr << " (sent by us)\n";
        break;

    default:
        ostr << '\n';
    }

    ostr << "   ARPHRD_type: " << header.ARPHRD_type << '\n'
         << "address_length: " << header.address_length << '\n';

    ostr << "       address: ";

    {
        auto guard = NetworkLib::Iosguard(ostr);

        ostr << std::hex << std::setfill('0');

        for (auto i = 0; i < header.address_length; ++i) {
            if (i > 0) {
                ostr << ':';
            }

            ostr << std::setw(2) << +(header.address[i]);
        }
    }

    ostr << '\n'
         << " protocol_type: " << EtherType::to_string(header.protocol_type);

    return ostr;
}

std::ostream &operator<<(std::ostream &ostr, const PcapHeader &header) {

    ostr << " Magic number: " << asHex32(header.magic_number) << '\n';

    ostr << "Version major: " << header.version_major << '\n'
         << "Version minor: " << header.version_minor << '\n'
         << "    This zone: " << header.thiszone << '\n'
         << "      Sigfigs: " << header.sigfigs << '\n'
         << " Snapshot len: " << header.snaplen << '\n'
         << "      Network: " << header.network;

    return ostr;
}

std::ostream &operator<<(std::ostream &ostr, const PcapRecord::Header &header) {
    ostr << "   ts_sec: " << header.ts_sec << '\n'
         << "  ts_usec: " << header.ts_usec << '\n'
         << " incl_len: " << header.incl_len << '\n'
         << " orig_len: " << header.orig_len;
    return ostr;
}

} // namespace NetworkLib

namespace DumperLib {

std::ostream &operator<<(std::ostream &ostr, const EthDumper &eth) {
    NetworkLib::EthFrameDecoder ethDecoder(eth.mBufferView);

    ostr << "+ Ethernet\n" << ethDecoder << '\n';

    if (ethDecoder.isIPv4()) {
        IPv4DumperProcessor processor(ostr);
        processor.consumeIPv4Packet(ethDecoder.getData());
    } else {
        ostr << "+ (UNKNOWN PROTOCOL) \n";
    }

    return ostr;
}

std::ostream &operator<<(std::ostream &ostr, const IPv4Dumper &ipv4) {
    IPv4DumperProcessor processor(ostr);
    processor.consumeIPv4Packet(ipv4.mBufferView);
    return ostr;
}

} // namespace DumperLib
} // namespace UPF
