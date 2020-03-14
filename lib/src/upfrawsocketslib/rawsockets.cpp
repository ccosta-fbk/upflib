#include <upfrawsocketslib/rawsockets.hh>

// For raw sockets constants and calls
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// For ioctl
#include <sys/ioctl.h>

// For if_nametoindex()
#include <net/if.h>

// For htons()
#include <arpa/inet.h>

// For std::memset() and std::strncpy()
#include <cstring>

// For std::runtime_error
#include <stdexcept>

// For std::ostringstream
#include <sstream>

// For std::array
#include <array>

namespace UPF {
namespace RawSocketsUtil {

IfIndex getIfIndexByIfName(const std::string &ifName) {
    const IfIndex result = if_nametoindex(ifName.c_str());

    if (result == 0) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": can't find ifIndex for ifName "
            << ifName;
        throw std::runtime_error(err.str());
    }

    return result;
}

std::string getIfNameByIfIndex(IfIndex ifIndex) {
    char buffer[IF_NAMESIZE];

    const char *result = if_indextoname(ifIndex, buffer);

    if (result == nullptr) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": can't find ifName for ifIndex "
            << ifIndex;
        throw std::runtime_error(err.str());
    }

    return std::string(buffer);
}

SocketFD openByIfIndex(IfIndex ifIdx, PromiscuousMode pmode) {
    // Open RAW socket first
    const SocketFD socketfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (socketfd == -1) {
        const int saved_errno = errno;
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": socket() error opening raw socket on ifIndex " << ifIdx
            << ": errno " << saved_errno << ": " << std::strerror(saved_errno);
        throw std::runtime_error(err.str());
    }

    try {
        // Then bind it to the given network interface
        struct sockaddr_ll socketAddress;
        std::memset(&socketAddress, 0, sizeof(socketAddress));
        socketAddress.sll_family = PF_PACKET;
        socketAddress.sll_ifindex = ifIdx;
        socketAddress.sll_protocol = htons(ETH_P_ALL);

        int rc =
            bind(socketfd, reinterpret_cast<struct sockaddr *>(&socketAddress),
                 sizeof(socketAddress));

        if (rc == -1) {
            const int saved_errno = errno;
            std::ostringstream err;
            err << NETWORKLIB_CURRENT_FUNCTION
                << ": bind() error on raw socket with fd" << socketfd
                << ": errno: " << saved_errno << ": "
                << std::strerror(saved_errno);

            throw std::runtime_error(err.str());
        }

        // Enable promiscuous mode on the interface, if requested
        if (pmode == PROMISCUOS_MODE_ENABLED) {

            struct packet_mreq packetMreq;
            std::memset(&packetMreq, 0, sizeof(packetMreq));

            packetMreq.mr_ifindex = ifIdx;
            packetMreq.mr_type = PACKET_MR_PROMISC;

            int rc = setsockopt(socketfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                                &packetMreq, sizeof(packetMreq));
            if (rc == -1) {
                const int saved_errno = errno;
                std::ostringstream err;
                err << NETWORKLIB_CURRENT_FUNCTION
                    << ": setsockopt() error on raw socket with fd" << socketfd
                    << ": errno: " << saved_errno << ": "
                    << std::strerror(saved_errno);
                throw std::runtime_error(err.str());
            }
        }

    } catch (std::exception &e) {
        // close socket first
        close(socketfd);

        // rethrow exception
        throw e;
    }

    return socketfd;
}

NetworkLib::BufferWritableView
receiveData(SocketFD socketfd,
            const NetworkLib::BufferWritableView &bufferWritableView) {
    const ssize_t ss =
        recv(socketfd, bufferWritableView.getUnderlyingWritableBufferPtr(),
             bufferWritableView.size(), 0);

    if (ss == -1) {
        const int saved_errno = errno;
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": recv() error on raw socket with fd" << socketfd
            << ": errno: " << saved_errno << ": " << std::strerror(saved_errno);
        throw std::runtime_error(err.str());
    } else if (ss < 0) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": recv() error on raw socket with fd" << socketfd
            << ": received a negative amount of data (" << ss << ')';
        throw std::runtime_error(err.str());
    }

    return bufferWritableView.getSub(0, static_cast<std::size_t>(ss));
}

void sendData(SocketFD socketfd, const NetworkLib::BufferView &bufferView) {
    const ssize_t ss = send(socketfd, bufferView.getUnderlyingBufferPtr(),
                            bufferView.size(), 0);

    if (ss < 0) {
        const int saved_errno = errno;
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": send() error on raw socket with fd" << socketfd
            << ": errno: " << saved_errno << ": " << std::strerror(saved_errno);
        throw std::runtime_error(err.str());
    }

    if (static_cast<std::size_t>(ss) < bufferView.size()) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": send() less bytes than expected on raw socket with fd"
            << socketfd << " (expected " << bufferView.size() << ", wrote "
            << ss << ")";
        throw std::runtime_error(err.str());
    }
}

void closeSocket(SocketFD socketfd) {
    int rc = close(socketfd);

    if (rc == -1) {
        const int saved_errno = errno;
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": close() error on raw socket with fd" << socketfd
            << ": errno: " << saved_errno << ": " << std::strerror(saved_errno);
        throw std::runtime_error(err.str());
    }
}

std::size_t getMTU(SocketFD socketfd, const std::string &ifName) {
    const char *function_name =
        "RawSocketsUtil::getMTU(RawSocketsUtil(RawSocketsUtil::SocketFD, const "
        "std::string &)";
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));

    std::strncpy(ifr.ifr_name, ifName.c_str(), sizeof(ifr.ifr_name));

    if (ioctl(socketfd, SIOCGIFMTU, &ifr) == -1) {
        const int saved_errno = errno;
        std::ostringstream err;
        err << function_name << ": ioctl(SIOCGIFMT) error on raw socket with fd"
            << socketfd << ": errno: " << saved_errno << ": "
            << std::strerror(saved_errno);
        throw std::runtime_error(err.str());
    }

    return ifr.ifr_mtu;
}

void setMTU(SocketFD socketfd, const std::string &ifName, std::size_t mtu) {
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, ifName.c_str(), sizeof(ifr.ifr_name));

    ifr.ifr_mtu = mtu;

    if (ioctl(socketfd, SIOCSIFMTU, &ifr) == -1) {
        const int saved_errno = errno;
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": ioctl(SIOCSIFMTU) error on raw socket with fd" << socketfd
            << ": errno: " << saved_errno << ": " << std::strerror(saved_errno);
        throw std::runtime_error(err.str());
    }
}

} // namespace RawSocketsUtil
} // namespace UPF
