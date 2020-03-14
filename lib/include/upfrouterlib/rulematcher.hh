#ifndef UPFROUTER_UPFROUTERLIB_RULEMATCHER_HH
#define UPFROUTER_UPFROUTERLIB_RULEMATCHER_HH

#include <upfnetworklib/networklib.hh>

#include <iterator>
#include <limits>
#include <list>

namespace UPF {
namespace UPFRouterLib {

/// @brief A rule matching a protocol, destination address and port.
struct MatchingRule {

    /// @brief The protocol number to match (0 = any)
    NetworkLib::IPv4Protocol::Type protocol = NetworkLib::IPv4Protocol::NONE;

    /// @brief CIDR to match against the destination address.
    NetworkLib::IPv4CIDR dstCidr;

    /// @brief Port number to match against the destination port (0 = any).
    ///
    /// It's meaningful only for IPv4 protocols using a port numbers
    /// (i.e. TCP/UDP/SCTP).
    NetworkLib::Port::Number dstPort = NetworkLib::Port::Invalid;

    /// @brief Constructor from a std::string.
    ///
    /// A rule is made by _protocol_-_address_/_mask_-_port_
    /// Example: `6-192.168.1.0/24-80`
    ///
    MatchingRule(const std::string &str);

    /// @brief Default constructor (create a rule matching any packet)
    MatchingRule() = default;
};

/// @brief Keeps a list of MatchingRule objects, and can tell if any of them
///        match against a given IPv4 packet.
class RuleMatcher {
  public:
    /// @brief Given a NetworkLib::IPv4Decoder attached to a IPv4 packet, tell
    ///        if there's any matching rule matching the given packet.
    bool match(const NetworkLib::IPv4Decoder &ipv4Decoder) const {

        // Iterate over rules to find a matching one.
        for (auto &&rule : mRules) {
            if (match(ipv4Decoder, rule)) {
                return true;
            }
        }

        // No rule matched.
        return false;
    }

    ///@name Rule list management
    ///
    ///@{

    /// @brief Constant to indicate the end of the list of rules.
    static const std::size_t endPosition =
        std::numeric_limits<std::size_t>::max();

    /// @brief Add a rule at the given position (0 = first).
    ///
    /// RuleMatcher::endPosition, or any number greater than the
    /// current numbers of rules, results in adding the rule at the
    /// end of the list.
    void addRule(const MatchingRule &rule, std::size_t position) {
        auto it = mRules.begin();

        if ((position == endPosition) || (position > mRules.size())) {
            it = std::end(mRules);
        } else {
            std::advance(it, position);
        }

        mRules.insert(it, rule);
    }

    /// @brief Delete a rule at the given position (0 = first).
    ///
    /// RuleMatcher::endPosition, or any number greater than the
    /// current numbers of rules, results in deleting the last rule in
    /// the list.
    void delRule(std::size_t position) {
        auto it = mRules.begin();

        if ((position == endPosition) || ((position + 1) > mRules.size())) {
            if (!mRules.empty()) {
                mRules.pop_back();
            }

            return;
        }

        std::advance(it, position);
        mRules.erase(it);
    }

    /// @brief Delete all rules (i.e. clear the rules list).
    void clearRules() { mRules.clear(); }

    ///@}

    /// @brief Provide read access to the list of rules
    const std::list<MatchingRule> &getRules() const { return mRules; }

  private:
    std::list<MatchingRule> mRules;

    bool match(const NetworkLib::IPv4Decoder &ipv4Decoder,
               const MatchingRule &matchingRule) const {

        // Try to match the protocol, if specified.
        if ((matchingRule.protocol != NetworkLib::IPv4Protocol::NONE) &&
            (matchingRule.protocol != ipv4Decoder.getProtocol())) {
            return false;
        }

        // Always match on destination address
        const NetworkLib::IPv4Address addressToMatch =
            ipv4Decoder.getDstAddress();

        // Try to match the address
        if (!matchingRule.dstCidr.matchAddress(addressToMatch)) {
            return false;
        }

        // Try to match a TCP/UDP/SCTP port if specified
        //
        // Note that specifying a port with protocols which are
        // neither TCP, nor UDP, nor SCTP will never result in a
        // match.
        if (matchingRule.dstPort != NetworkLib::Port::Invalid) {
            NetworkLib::Port::Number packetPort = {NetworkLib::Port::Invalid};

            if (ipv4Decoder.isTCP()) {
                NetworkLib::TCPDecoder tcpDecoder(ipv4Decoder.getData());
                packetPort = tcpDecoder.getDstPort();
            } else if (ipv4Decoder.isUDP()) {
                NetworkLib::UDPDecoder udpDecoder(ipv4Decoder.getData());
                packetPort = udpDecoder.getDstPort();
            } else if (ipv4Decoder.isSCTP()) {
                NetworkLib::SCTPDecoder sctpDecoder(ipv4Decoder.getData());
                packetPort = sctpDecoder.getDstPort();
            }

            if (matchingRule.dstPort != packetPort) {
                return false;
            }
        }

        // Everything matches.
        return true;
    }
};

} // namespace UPFRouterLib
} // namespace UPF

#endif
