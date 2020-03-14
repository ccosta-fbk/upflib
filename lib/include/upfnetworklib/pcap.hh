#ifndef UPFNETWORKLIB_PCAP
#define UPFNETWORKLIB_PCAP

#include <upfnetworklib/buffers.hh>
#include <upfnetworklib/ethernet.hh>
#include <upfnetworklib/interfaces.hh>
#include <upfnetworklib/utils.hh>

#include <string>

#include <fstream>

#include <array>

namespace UPF {
namespace NetworkLib {

/**
 * @brief The global header in a ``.pcap`` file.
 */
struct PcapHeader {

    /// @brief Magic number.
    ///
    /// It tells this is a .pcap file. It tells also the endianess
    /// of data in the headers and the time resolution.
    std::uint32_t magic_number;

    /// @brief Major version
    std::uint16_t version_major;

    /// @brief Minor version
    std::uint16_t version_minor;

    /// @brief Timezeone
    std::int32_t thiszone;

    /// @brief Number of significative figures in timestamps
    std::uint32_t sigfigs;

    /// @brief Maximum length of each captured packet.
    std::uint32_t snaplen;

    /// @brief Kind of captured data.
    std::uint32_t network;

    /// @brief Invert endianess on header fields.
    ///
    /// A libpcap header is stored with the capturing host
    /// endianess, so it may need to be adjusted before being used
    /// according to the pcap file magic number.
    void swapByteOrder() {
        magic_number = NetworkLib::swapByteOrder(magic_number);
        version_major = NetworkLib::swapByteOrder(version_major);
        version_minor = NetworkLib::swapByteOrder(version_minor);
        thiszone = NetworkLib::swapByteOrder(thiszone);
        sigfigs = NetworkLib::swapByteOrder(sigfigs);
        snaplen = NetworkLib::swapByteOrder(snaplen);
        network = NetworkLib::swapByteOrder(network);
    }

    /// @brief Known values for member ``magic_number``, indicating endianess
    /// and time
    ///         resolution.
    enum {
        Magic_NoSwap_NoNanoSec = 0xa1b2c3d4,
        Magic_Swap_NoNanoSec = 0xd4c3b2a1,
        Magic_NoSwap_NanoSec = 0xa1b23c4d,
        Magic_Swap_NanoSec = 0x4d3cb2a1,
    };

    /// @brief Supported values for member ``network``, indicating the content
    ///        type of records.
    enum {
        // Raw Ethernet frames
        Network_Ethernet = 0x1,

        // L3 packets, preceded by a special header with L2 info.
        Network_LinuxCooked = 0x71,
    };

} NETWORKLIB_PACKED_ATTRIBUTE;

/**
 * @brief A record in a ``.pcap`` file
 *
 * @note It's guaranteed that member ``data``, containing L3 data, will
 *       start in memory at the very same point as the given
 *       BufferWritableView specified in the constructor.
 */
struct PcapRecord {
    ///@name Constructors

    /// @brief Constructor specifying a BufferWritableView where a single
    ///        record can be read.
    PcapRecord(BufferWritableView &b) : data(b) {}

    ///@}

    ///@name Copy semantic
    ///@{
    PcapRecord(const PcapRecord &) = default;
    PcapRecord &operator=(const PcapRecord &) = default;
    ///@}

    ///@name Move semantic
    ///@{
    PcapRecord(PcapRecord &&) = default;
    PcapRecord &operator=(PcapRecord &&) = default;
    ///@}

    /// @brief A .pcap record header (for each captured packet).
    ///
    /// Note: struct is read from file with a raw read: members and
    ///       member order is important, as
    ///       NETWORKLIB_PACKED_ATTRIBUTE below.
    struct Header {
        /// @brief Capture timestamp (seconds).
        std::uint32_t ts_sec;

        /// @brief Capture timestamp (microseconds).
        std::uint32_t ts_usec;

        /// @brief Data length.
        std::uint32_t incl_len;

        /// @brief Original length of the captured packet.
        std::uint32_t orig_len;

        /// @brief Invert endianess on header fields.
        ///
        /// A libpcap header is stored with the capturing host
        /// endianess, so it may need to be adjusted before being used
        /// according to the magic number in the pcap file header.
        void swapByteOrder() {
            ts_sec = NetworkLib::swapByteOrder(ts_sec);
            ts_usec = NetworkLib::swapByteOrder(ts_usec);
            incl_len = NetworkLib::swapByteOrder(incl_len);
            orig_len = NetworkLib::swapByteOrder(orig_len);
        }
    } NETWORKLIB_PACKED_ATTRIBUTE;

    /// @brief A Linux "cooked" pseudo-L2 header
    ///
    /// Note: struct is read from file with a raw read: members and
    ///       member order is important, as
    ///       NETWORKLIB_PACKED_ATTRIBUTE below.
    ///
    /// Data on file is ALWAYS in network order, regardless of the
    /// magic number in the pcap general header.
    struct LinuxCooked {
        /// @brief Type of packet (i.e. direction)
        ///
        /// * 0: packet from someone else specifically sent to us;
        /// * 1: broadcast from someone else;
        /// * 2: multicast from someone else;
        /// * 3: packet from someone else for someone else;
        /// * 4: packet from us.
        std::uint16_t packet_type;

        /// @brief L2 address type (1 = Ethernet MAC Address)
        std::uint16_t ARPHRD_type;

        /// @brief L2 total address length.
        std::uint16_t address_length;

        /// @brief Buffer for the first 8 bytes of L2 address value.
        std::array<unsigned char, 8> address;

        /// @brief The kind of packet in the record
        EtherType::Type protocol_type;

        /// @brief Convert between network order and host order, and
        ///        vice versa (if they are not the same).
        ///
        /// On a big endian architecture it does nothing.  On a little
        /// endian architecture, it swaps byte order.
        void swapByteOrderIfNeeded() {
            packet_type = getUint16At(&packet_type);
            ARPHRD_type = getUint16At(&ARPHRD_type);
            address_length = getUint16At(&address_length);
            protocol_type = EtherType::Type(getUint16At(&protocol_type));
        }
    } NETWORKLIB_PACKED_ATTRIBUTE;

    /// @brief Data for the .pcap record header
    Header pcapRecordHeader;

    /// @brief Data for the Linux Cooked header, if any
    LinuxCooked linuxCookedHeader;

    /// @brief Record payload (the packet data).
    BufferWritableView data;
};

/**
 * @brief A very simple reader of .pcap files not depending on libpcap.
 *
 * It supports only a few capture types (i.e. Ethernet (1), raw IP (101), Linux
 * "cooked" capture encapsulation (113)).
 *
 * It can read the same .pcap once (default), or more times, or
 * infinite times.
 */
class PcapReader {
  public:
    ///@name Constructors
    ///@{

    /// @brief Construcor specifying the name of a .pcap file to read,
    ///        and the number of times it must be read (default: 1).
    ///
    /// @param filename Path of the .pcap file to read.
    ///
    /// @param repeats Number of times the .pcap file should be read.
    ///        Default is 1. `0` means "infinite" times.
    PcapReader(const std::string &filename, std::size_t repeats = 1);

    ///@}

    /// @brief Read next captured packet using the given buffer.
    ///
    /// The payload is then available in member 'data' of the
    /// resulting record.
    ///
    /// Throws exceptions on errors.
    PcapRecord readRecord(BufferWritableView &buffer);

    /// @brief Return true if there are more records to read.
    bool moreRecords();

    /// @brief Get a const reference to the .pcap global header
    const PcapHeader &getHeader() const { return mHeader; }

  private:
    // Input stream
    std::ifstream mIStream;

    // Number of time we have to loop over all records (0 = infinte)
    std::size_t mRepeats;

    // Number of times we looped so far.
    std::size_t mLoopCount = 0;

    // Position of the first record.
    std::ifstream::pos_type mBeginOfRecords;

    // The global header for this file (adjusted for endianess)
    PcapHeader mHeader;

    // True when we need to fix endianess
    bool mNeedsSwapping;

    // True when timestamps in file have nanoseconds resolution
    // (encoded in the magic number)
    bool mNanoSecResolution;

    /////////////
    // Methods //
    /////////////

    // Read the global header (adjusting endianess)
    void readHeader();
};

/**
 * @brief A very simple writer of .pcap files not depending on libpcap.
 *
 * It can write out either IPv4 data or Ethernet data.
 *
 * It supports only a few capture types (i.e. Ethernet (1), Linux
 * "cooked" capture encapsulation (113)).
 */
class PcapWriter {
  public:
    /// @brief The kind of data being fed to the writer.
    enum class WriteMode {
        IPv4 = 0,
        Ethernet = 1,
    };

    ///@name Constructors
    ///@{

    /// @brief Constructor specifying the name of a output file and
    ///        the kind of records being written out.
    PcapWriter(const std::string &filename, WriteMode mode);

    ///@}

    /// @brief Write out a .pcap record.
    ///
    /// It's either IPv4 data or Ethernet data according to the
    /// WriteMode used to create this PcapWriter
    PcapWriter &writeRecord(const BufferView &data);

    /// @brief Force closing the .pcap file
    void close() { mOStream.close(); }

  private:
    WriteMode mWriteMode;
    bool mHeaderWritten;
    std::ofstream mOStream;

    void writeHeader();
};

////////////////////////////////
// Ethernet Writer and Reader //
////////////////////////.///////

/**
 * @brief A wrapper around PcapWriter acting as a EthPacketSink.
 */
class PcapEthWriter : public EthPacketSink {
  public:
    ///@name Constructors
    ///@{

    /// @brief Constructor specifying a .pcap filename to write
    PcapEthWriter(const std::string &filename)
        : mWriter(filename, PcapWriter::WriteMode::Ethernet) {}

    ///@}

    virtual ~PcapEthWriter() {}

    ///@name EthPacketSink interface
    ///@{

    /// @brief Feed Ethernet traffic to this writer.
    ///
    /// @param ethData A BufferView with the Ethernet data to be
    ///        written out.
    ///
    /// @param userData Ignored.
    virtual void consumeEthPacket(
        const BufferView &ethData,
        ContextUserData &userData = defaultContextUserData) override {
        (void)userData;
        mWriter.writeRecord(ethData);
    }

    ///@}

  private:
    PcapWriter mWriter;
};

/**
 * @brief A wrapper around PcapWriter acting both a EthPacketSink and
 *        as an IPv4PacketSink.

 * When consuming IPv4 packets, use user-provided source and
 * desination MAC addresses.
 */
class PcapEthWriterPlus : public EthPacketSink, public IPv4PacketSink {
  public:
    ///@name Constructors
    ///@{

    /// @brief Constructor specifying a .pcap filename to write
    PcapEthWriterPlus(const std::string &filename)
        : mWriter(filename, PcapWriter::WriteMode::Ethernet) {}

    ///@}

    virtual ~PcapEthWriterPlus() {}

    ///@name EthPacketSink interface
    ///@{

    /// @brief Feed Ethernet traffic to this writer.
    ///
    /// @param ethData A BufferView with the Ethernet data to be
    ///        written out.
    ///
    /// @param userData Ignored.
    virtual void consumeEthPacket(
        const BufferView &ethData,
        ContextUserData &userData = defaultContextUserData) override {
        (void)userData;
        mWriter.writeRecord(ethData);
    }

    ///@name IPv4PacketSink interface
    ///@{

    /// @brief Feed IPv4 traffic to this writer.
    ///
    /// The IPv4 traffic is written out encapsulated in a fake
    /// Ethernet frame, using the default source and destination
    /// MACAddress
    ///
    /// @param ipv4Data A BufferView with the ipv4 data to be
    ///        written out.
    ///
    /// @param userData Ignored.
    ///
    /// @see setDefaultSrcAddress(), setDefaultDstAddress()
    virtual void consumeIPv4Packet(
        const BufferView &ipv4Data,
        ContextUserData &userData = defaultContextUserData) override;

    ///@}

    ///@name Default MAC addresses
    ///@{

    /// @brief Set the fake source MAC address to be used when
    ///        consuming IPV4 packets.
    ///
    /// The default value is 00:00:00:00:00:00
    void setDefaultSrcAddress(const MACAddress &a) { mDefaultSrc = a; }

    /// @brief Set the fake destination MAC address to be used when
    ///        consuming IPV4 packets.
    ///
    /// The default value is 00:00:00:00:00:00
    void setDefaultDstAddress(const MACAddress &a) { mDefaultDst = a; }

    ///@}

  private:
    PcapWriter mWriter;

    // Default source and destination Ethernet address for when
    // writing out IPV4 data
    MACAddress mDefaultSrc{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    MACAddress mDefaultDst{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    PacketBufferArrayBased<65600> mEthBuffer;
};

/**
 * @brief A wrapper aound PcapReader acting as a EthPacketSource.
 */
class PcapEthReader : public EthPacketSource {
  public:
    ///@name Constructors
    ///@{

    /// @brief Construcor specifying the name of a .pcap file to read,
    ///        and the number of times it must be read (default: 1).
    ///
    /// @param filename Path of the .pcap file to read.
    ///
    /// @param repeats Number of times the .pcap file should be read.
    ///        Default is 1. `0` means "infinite" times.
    PcapEthReader(std::string filename, std::size_t repeats = 1)
        : mReader(filename, repeats) {}

    ///@}

    virtual ~PcapEthReader() {}

    /// @brief Get the snapshot length of all packets in the .pcap
    ///        file.
    ///
    /// This is basically the maximum length of the data in a single
    /// .pcap record. It comes useful to provide BufferWritableView
    /// of a suitable size when reading data.
    std::size_t getSnapLen() const { return mReader.getHeader().snaplen; }

    /// @brief EthPacketSource interface
    virtual bool packetAvailable() override { return mReader.moreRecords(); }

    ///@name Implement EthPacketSource interface.
    ///@{
    virtual BufferWritableView
    getEthPacket(BufferWritableView &buffer) override;

    ///@}

  private:
    PcapReader mReader;

    // This is use as a fake Ethernet destination address in the
    // cases it's not known (i.e. LinuxCooked captures)
    static const NetworkLib::MACAddress mFakeEthDst;

    // This is used as a fake Ethernet source address in the (rare)
    // cases it's not known (i.e. LinuxCooked captures with unexpected
    // values of ARPHDR_type and address_lenght).
    static const NetworkLib::MACAddress mFakeEthSrc;
};

////////////////////////////
// IPv4 Writer and Reader //
////////////////////////////

/**
 * @brief A wrapper around PcapWriter acting as a IPv4PacketSink.
 */
class PcapIPv4Writer : public IPv4PacketSink {
  public:
    ///@name Constructors
    ///@{

    /// @brief Constructor specifying a .pcap filename to write.
    PcapIPv4Writer(const std::string &filename)
        : mWriter(filename, PcapWriter::WriteMode::IPv4) {}

    ///@}

    virtual ~PcapIPv4Writer() {}

    ///@name IPv4PacketSink interface
    ///@{
    virtual void consumeIPv4Packet(
        const BufferView &ipv4Data,
        ContextUserData &userData = defaultContextUserData) override {
        (void)userData;

        mWriter.writeRecord(ipv4Data);
    }

    ///@}

  private:
    PcapWriter mWriter;
};

/**
 * @brief A wrapper around PcapReader acting as a IPv4PacketSource.
 */
class PcapIPv4Reader : public IPv4PacketSource {
  public:
    ///@name Constructors
    ///@{

    /// @brief Construcor specifying the name of a .pcap file to read,
    ///        and the number of times it must be read (default: 1).
    ///
    /// @param filename Path of the .pcap file to read.
    ///
    /// @param repeats Number of times the .pcap file should be read.
    ///        Default is 1. `0` means "infinite" times.
    PcapIPv4Reader(std::string filename, std::size_t repeats = 1)
        : mReader(filename, repeats) {}

    ///@}

    virtual ~PcapIPv4Reader() {}

    ///@name IPv4PacketSource interface.
    ///@{

    ///@brief True if more packets are available
    virtual bool packetAvailable() override { return mReader.moreRecords(); }

    /// @brief Read a packet
    ///
    /// @param buffer The packet will be read in this BufferWritableView.
    ///
    /// @return A BufferWritableView as large as the packet.
    virtual BufferWritableView
    getIPv4Packet(BufferWritableView &buffer) override;

    ///@}

  private:
    PcapReader mReader;
};

} // namespace NetworkLib
} // namespace UPF

#endif
