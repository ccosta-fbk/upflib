#include <upfnetworklib/pcap.hh>

#include <upfnetworklib/ethernet.hh>

// For std::ostringstream
#include <sstream>

// For std::char_traits<>()
#include <string>

#include <chrono>

#include <iostream>

namespace UPF {
namespace NetworkLib {

PcapReader::PcapReader(const std::string &filename, std::size_t repeats)
    : mIStream(filename, std::ios::binary), mRepeats(repeats) {
    // First, read the global header
    readHeader();

    // Remember the position where the records start (for looping)
    mBeginOfRecords = mIStream.tellg();
}

void PcapReader::readHeader() {
    mIStream.read(reinterpret_cast<char *>(&mHeader), sizeof(mHeader));

    switch (mHeader.magic_number) {
    case PcapHeader::Magic_NoSwap_NoNanoSec:
        mNeedsSwapping = false;
        mNanoSecResolution = false;
        break;

    case PcapHeader::Magic_Swap_NoNanoSec:
        mNeedsSwapping = true;
        mNanoSecResolution = false;
        break;

    case PcapHeader::Magic_NoSwap_NanoSec:
        mNeedsSwapping = false;
        mNanoSecResolution = true;
        break;

    case PcapHeader::Magic_Swap_NanoSec:
        mNeedsSwapping = true;
        mNanoSecResolution = true;
        break;

    default:
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": unknown pcap magic number "
            << asHex32(mHeader.magic_number);
        throw std::runtime_error(err.str());
    }

    if (mNeedsSwapping) {
        mHeader.swapByteOrder();
    }
}

PcapRecord PcapReader::readRecord(BufferWritableView &buffer) {
    const bool atEOF1 = (mIStream.peek() == std::char_traits<char>::eof());

    if (atEOF1) {
        mLoopCount++;

        if (mLoopCount < mRepeats) {

            // Clear status bits
            mIStream.clear();

            // Seek to beginning of records
            mIStream.seekg(mBeginOfRecords);

        } else if (mRepeats == 0) {
            // Clear status bits
            mIStream.clear();

            // Seek to beginning of records
            mIStream.seekg(mBeginOfRecords);
        }
    }

    const bool atEOF2 = (mIStream.peek() == std::char_traits<char>::eof());

    if (atEOF2) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": can't read full record header";
        throw std::runtime_error(err.str());
    }

    PcapRecord result(buffer);

    // An alias to make code shorter.
    PcapRecord::Header &header = result.pcapRecordHeader;

    std::size_t bytesRead;

    // First: read in the record header
    mIStream.read(reinterpret_cast<char *>(&header), sizeof(header));
    bytesRead = mIStream.gcount();

    if (bytesRead < sizeof(header)) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": can't read full record header";
        throw std::runtime_error(err.str());
    }

    if (mNeedsSwapping) {
        header.swapByteOrder();
    }

    std::size_t dataLength = header.incl_len;

    // If it's the case, read in the LinuxCooked header
    if (mHeader.network == PcapHeader::Network_LinuxCooked) {

        if (dataLength < sizeof(result.linuxCookedHeader)) {
            std::ostringstream err;
            err << NETWORKLIB_CURRENT_FUNCTION
                << ": can't read LinuxCooked header (malformed header?)";
            throw std::runtime_error(err.str());
        }

        mIStream.read(reinterpret_cast<char *>(&result.linuxCookedHeader),
                      sizeof(result.linuxCookedHeader));
        bytesRead = mIStream.gcount();
        dataLength -= bytesRead;

        if (bytesRead < sizeof(result.linuxCookedHeader)) {
            std::ostringstream err;
            err << "can't read LinuxCooked header (premature EOF?)";
            throw std::runtime_error(err.str());
        }

        result.linuxCookedHeader.swapByteOrderIfNeeded();
    }

    // Skip the packet data if it's too long for our buffer, and
    // throw an exception
    if (dataLength > buffer.size()) {
        mIStream.ignore(dataLength);

        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": skipping record which is too long for buffer ("
            << "(" << dataLength << " required, " << buffer.size()
            << " available)";
        throw std::length_error(err.str());
    }

    // Attempt to read the packet in the given buffer
    mIStream.read(
        reinterpret_cast<char *>(buffer.getUnderlyingWritableBufferPtr()),
        dataLength);
    bytesRead = mIStream.gcount();

    // Throw an exception if we couldn't read a whole packet
    if (bytesRead < dataLength) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": couldn't read whole packet (EOF?)";
        throw std::runtime_error(err.str());
    }

    // Throw an exception also if the packet is longer than
    // the capture length (use header.incl_len here as the
    // capture length includes the Linux Cooked header)
    if (header.incl_len > mHeader.snaplen) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": record is longer than snapshot size ("
            << "(" << header.incl_len << " required, " << buffer.size()
            << " available)";
        throw std::runtime_error(err.str());
    }

    // Note: is is VERY important that the offset (first argument to
    //       getSub() is 0.
    result.data = buffer.getSub(0, dataLength);
    return result;
}

bool PcapReader::moreRecords() {

    const bool atEOF = (mIStream.peek() == std::char_traits<char>::eof());

    if (atEOF) {
        if ((mRepeats == 0) || ((mLoopCount + 1) < mRepeats)) {

            // Clear status bits, since we are at EOF
            // but we want to repeat
            mIStream.clear();

            return true;

        } else {
            // We have reached the end of loops
            return false;
        }
    } else {
        // Not at EOF, go on
        return true;
    }
}

//////////////////////
// class PcapWriter //
//////////////////////

PcapWriter::PcapWriter(const std::string &filename, WriteMode mode)
    : mWriteMode{mode}, mHeaderWritten{false},
      mOStream(filename, std::ios::binary | std::ios::out) {}

void PcapWriter::writeHeader() {
    PcapHeader header = {};

    header.magic_number = PcapHeader::Magic_NoSwap_NoNanoSec;
    header.version_major = 2;
    header.version_minor = 4;
    header.thiszone = 0;
    header.sigfigs = 0;
    header.snaplen = 262144;

    if (mWriteMode == WriteMode::IPv4) {
        header.network = PcapHeader::Network_LinuxCooked;
    } else if (mWriteMode == WriteMode::Ethernet) {
        header.network = PcapHeader::Network_Ethernet;
    }

    mOStream.write(reinterpret_cast<const char *>(&header), sizeof(header));
}

PcapWriter &PcapWriter::writeRecord(const BufferView &data) {
    // Write out header if not already written
    if (!mHeaderWritten) {
        writeHeader();
        mHeaderWritten = true;
    }

    std::chrono::high_resolution_clock::time_point epoch;
    const auto currentTime = std::chrono::high_resolution_clock::now();
    const auto deltaTime = currentTime - epoch;

    std::uint32_t dataLength = data.size();

    if (mWriteMode == WriteMode::IPv4) {
        dataLength = dataLength + sizeof(PcapRecord::LinuxCooked);
    }

    // Prepare a generic header
    PcapRecord::Header header = {};
    header.ts_sec =
        std::chrono::duration_cast<std::chrono::seconds>(deltaTime).count();
    header.ts_usec = std::chrono::duration_cast<std::chrono::microseconds>(
                         deltaTime % std::chrono::seconds(1))
                         .count();

    header.incl_len = dataLength;
    header.orig_len = dataLength;

    mOStream.write(reinterpret_cast<const char *>(&header), sizeof(header));

    if (mWriteMode == WriteMode::IPv4) {
        // Since we don't have any L2 info available,
        // let's fill in some reasonable default values.
        PcapRecord::LinuxCooked linuxCooked = {};

        // Always "sent by us"
        linuxCooked.packet_type = 4;

        // Alway "Ethernet MAC Address";
        linuxCooked.ARPHRD_type = 1;

        // Always 6 bytes
        linuxCooked.address_length = 6;

        // Note: linuxCooked.address is already zeroed out, and we
        //       don't really have a MAC address to write out
        linuxCooked.address = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe};

        // Always IPv4
        linuxCooked.protocol_type = EtherType::IPv4;

        linuxCooked.swapByteOrderIfNeeded();

        mOStream.write(reinterpret_cast<const char *>(&linuxCooked),
                       sizeof(linuxCooked));
    }

    mOStream.write(
        reinterpret_cast<const char *>(data.getUnderlyingBufferPtr()),
        data.size());
    return *this;
    ;
}

/////////////////////////
// class PcapEthReader //
/////////////////////////

const NetworkLib::MACAddress PcapEthReader::mFakeEthSrc{0xde, 0xad, 0xbe,
                                                        0xef, 0xca, 0xfe};
const NetworkLib::MACAddress PcapEthReader::mFakeEthDst{0xde, 0xad, 0xbe,
                                                        0xef, 0xca, 0xfe};

BufferWritableView PcapEthReader::getEthPacket(BufferWritableView &buffer) {
    BufferWritableView result;

    const std::uint32_t &network = mReader.getHeader().network;

    // Leave room for a fake minimal Ethernet header.
    // This means: 6 bytes for dst address, 6 bytes for src address,
    // 2 bytes for ethertype => 14 bytes.
    const std::size_t eth_headerLength = 14;

    if (network == PcapHeader::Network_Ethernet) {
        // Just read the Ethernet frame flat out
        PcapRecord record = mReader.readRecord(buffer);
        result = record.data;
    } else if (network == PcapHeader::Network_LinuxCooked) {
        // Read data filling in a fake Ethernet header.

        // First, prepare a sub-buffer for data at the right offset.
        //
        // Note: this also implicitly verifies that
        //       buffer.size() >= eth_headerLength
        BufferWritableView subBuffer = buffer.getSub(eth_headerLength);

        // Read in L3 data directly at the right offset
        PcapRecord record = mReader.readRecord(subBuffer);

        // Destination MAC address. It's always unknown in this case.
        buffer.setMACAddressAt_nocheck(0, mFakeEthDst);

        // Alias
        const PcapRecord::LinuxCooked &lc = record.linuxCookedHeader;

        // Source MAC address. It's often known in this case
        if (lc.ARPHRD_type == 1 && lc.address_length == 6) {
            // Set source MAC address from record
            buffer.setMACAddressAt_nocheck(
                6, NetworkLib::MACAddress(lc.address[0], lc.address[1],
                                          lc.address[2], lc.address[3],
                                          lc.address[4], lc.address[5]));
        } else {
            // Set a fake source MAC address
            buffer.setMACAddressAt_nocheck(6, mFakeEthSrc);
        }

        // Set the protocol from Linux Cooked header
        buffer.setUint16At_nocheck(12, record.linuxCookedHeader.protocol_type);

        // Return a shrinked buffer
        result = buffer.getSub(0, eth_headerLength + record.data.size());
    }

    return result;
}

//////////////////////////
// class PcapIPv4Reader //
//////////////////////////

BufferWritableView PcapIPv4Reader::getIPv4Packet(BufferWritableView &buffer) {
    PcapRecord record = mReader.readRecord(buffer);

    BufferWritableView result;

    const std::uint32_t &network = mReader.getHeader().network;

    if (network == PcapHeader::Network_Ethernet) {
        EthFrameDecoder ethDecoder(record.data);
        if (ethDecoder.isIPv4()) {
            result = buffer.getSub(ethDecoder.getDataOffset(),
                                   ethDecoder.getDataLengthBytes());
        }

    } else if (network == PcapHeader::Network_LinuxCooked) {
        if (record.linuxCookedHeader.protocol_type == EtherType::IPv4) {
            result = record.data;
        }
    }

    return result;
}

/////////////////////////////
// class PcapEthWriterPlus //
/////////////////////////////

void PcapEthWriterPlus::consumeIPv4Packet(const BufferView &ipv4Data,
                                          ContextUserData &) {
    constexpr std::size_t ethHeaderLength = 14;
    constexpr std::size_t srcMACAddressOffset = 6;
    constexpr std::size_t dstMACAddressOffset = 0;
    constexpr std::size_t etherTypeOffset = 12;
    constexpr std::uint16_t ipv4EtherType = 0x0800;

    // Check there's enough room in the Ethernet buffer
    // for the given IPv4 data
    if ((ipv4Data.size() + ethHeaderLength) > mEthBuffer.size()) {
        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION
            << ": skipping record which is too long for buffer ("
            << "(" << (ipv4Data.size() + ethHeaderLength) << " required, "
            << mEthBuffer.size() << " available)";
        throw std::length_error(err.str());
    }

    BufferWritableView ethData =
        BufferWritableView::makeNonOwningBufferWritableView(mEthBuffer.data(),
                                                            mEthBuffer.size());
    ethData.setMACAddressAt_nocheck(dstMACAddressOffset, mDefaultDst);
    ethData.setMACAddressAt_nocheck(srcMACAddressOffset, mDefaultSrc);
    ethData.setUint16At_nocheck(etherTypeOffset, ipv4EtherType);

    // Copy the IPv4 data into the Ethernet buffer.
    ipv4Data.copyTo(0, ipv4Data.size(),
                    ethData.getUnderlyingWritableBufferPtr() + ethHeaderLength);
    ethData.shrinkTo(ipv4Data.size() + ethHeaderLength);

    mWriter.writeRecord(ethData);
}

} // namespace NetworkLib
} // namespace UPF
