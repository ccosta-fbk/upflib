#ifndef UPFRAWSOCKETSLIB_HH
#define UPFRAWSOCKETSLIB_HH

#include <upfnetworklib/networklib.hh>

// For std::size_t
#include <cstddef>

// For std::string
#include <string>

namespace UPF {

/// @brief A set of **platform-specific** utilites for dealing with
///        raw sockets.
namespace RawSocketsUtil {

/// @brief A type representing an ifIndex.
typedef unsigned int IfIndex;

/// @brief A type representing a Unix file descriptor of a socket.
typedef int SocketFD;

/// @brief Promiscuos mode when opening a raw socket.
enum PromiscuousMode {
    PROMISCUOS_MODE_DISABLED = 0,
    PROMISCUOS_MODE_ENABLED = 1
};

/// @brief Open a raw socket for getting all traffic received by the
///         interface with the given ifIndex.
///
/// Throw std::runtime_error on errors.
SocketFD openByIfIndex(IfIndex ifIdx, PromiscuousMode mode);

/// @brief Get an ifIndex out of an ifName.
///
/// Throws std::runtime_error if the specified interface can't be
/// found.
IfIndex getIfIndexByIfName(const std::string &ifName);

/// @brief Get an ifName out of an ifIndex.
///
/// Throw std::runtime_error if given interface can't be found.
std::string getIfNameByIfIndex(IfIndex ifIndex);

/// @brief Receive traffic from a raw socket and store it into the
///        given BufferWritableView.
///
/// @return A different BufferWritableView (on the same underlying
///         PacketBuffer) with the actual data read.
///
/// Throw std::runtime_error on errors.
NetworkLib::BufferWritableView
receiveData(SocketFD socketfd,
            const NetworkLib::BufferWritableView &bufferWritableView);

/// @brief Send traffic to a raw socket.
///
/// Throws std::runtime_error on errors
void sendData(SocketFD, const NetworkLib::BufferView &bufferView);

/// @brief Close a raw socket.
void closeSocket(SocketFD socketfd);

/// @brief Get the MTU current value on the interface having the given
///        ifname.
///
/// Throw std::runtime_error on errors.
std::size_t getMTU(SocketFD, const std::string &ifName);

/// @brief Set the MTU current value on the given interface.
void setMTU(SocketFD, const std::string &ifName, std::size_t mtu);
} // namespace RawSocketsUtil
} // namespace UPF

#endif // UPFRAWSOCKETSLIB_HH
