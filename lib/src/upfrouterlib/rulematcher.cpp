#include <upfdumperlib/dumper.hh>
#include <upfrouterlib/rulematcher.hh>

#include <algorithm>
#include <iterator>

namespace UPF {
namespace UPFRouterLib {

static MatchingRule parseMatchingRule(
    std::pair<std::string::const_iterator, std::string::const_iterator> range) {

    auto const it = range.first;
    auto const end = range.second;

    MatchingRule result;

    auto r1 = std::find(it, end, '-');

    if (r1 == end) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": missing protocol number";
        throw std::invalid_argument(err.str());
    }

    std::string strProtocol(it, r1);

    if (strProtocol == "*") {
        result.protocol = NetworkLib::IPv4Protocol::NONE;
    } else {
        unsigned long p = std::stoul(strProtocol);
        if (p <= 255) {
            result.protocol = NetworkLib::IPv4Protocol::Type(p);
        } else {
            std::ostringstream err;
            err << NETWORKLIB_CURRENT_FUNCTION << ": invalid protocol number";
            throw std::invalid_argument(err.str());
        }
    }

    r1++;
    auto r2 = std::find(r1, end, '/');

    if (r2 == end) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": missing CIDR";
        throw std::invalid_argument(err.str());
    }

    std::string strAddress(r1, r2);
    NetworkLib::IPv4Address addr(strAddress);

    r2++;
    auto r3 = std::find(r2, end, '-');

    if (r3 == end) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": missing port number";
        throw std::invalid_argument(err.str());
    }

    std::string strMask(r2, r3);
    unsigned long m = std::stoul(std::string(r2, r3));

    if (m > 32) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": CIDR mask too large";
        throw std::invalid_argument(err.str());
    }

    result.dstCidr = NetworkLib::IPv4CIDR(addr, static_cast<unsigned int>(m));

    r3++;

    if (r3 == end) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": missing port number";
        throw std::invalid_argument(err.str());
    }

    std::string strPort(r3, end);

    if (strPort == "*") {
        result.dstPort = NetworkLib::Port::Invalid;
    } else {
        unsigned long p = std::stoul(strPort);

        if (p == 0) {
            result.dstPort = NetworkLib::Port::Invalid;
        } else if (p < 1 || p > 65535) {
            std::ostringstream err;
            err << NETWORKLIB_CURRENT_FUNCTION << ": invalid port number";
            throw std::invalid_argument(err.str());
        }

        result.dstPort = NetworkLib::Port::Number(p);
    }

    return result;
}

MatchingRule::MatchingRule(const std::string &str) {
    *this = parseMatchingRule(NetworkLib::trim(str));
}

} // namespace UPFRouterLib
} // namespace UPF
