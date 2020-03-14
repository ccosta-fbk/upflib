#ifndef UPFNETWORKLIB_SCTP_HH
#define UPFNETWORKLIB_SCTP_HH

#include <upfnetworklib/buffers.hh>
#include <upfnetworklib/ipv4.hh>
#include <upfnetworklib/utils.hh>

#include <ostream>
#include <vector>

namespace UPF {
namespace NetworkLib {

/// @brief Namespace for SCTP chunk types.
namespace SCTPChunk {
/// @brief A type for storing a SCTP chunk type, with known values.
///
/// (see also
/// https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-1)
enum Type : std::uint8_t {
    DATA = 0,
    INIT = 1,
    INIT_ACK = 2,
    SACK = 3,
    HEARTBEAT = 4,
    HEARTBEAT_ACK = 5,
    ABORT = 6,
    SHUTDOWN = 7,
    SHUTDOWN_ACK = 8,
    ERROR = 9,
    COOKIE_ECHO = 10,
    COOKIE_ACK = 11,
    ECNE = 12,
    CWR = 13,
    SHUTDOWN_COMPLETE = 14,
    AUTH = 15,
    I_DATA = 64,
    ASCONF_ACK = 128,
    RE_CONFIG = 130,
    PAD = 132,
    FORWARD_TSN = 192,
    ASCONF = 193,
    I_FORWARD_TSN = 194,
};
} // namespace SCTPChunk

/**
 * @brief Decode a generic SCTP chunk stored in a BufferView
 */
class SCTPGenericChunkDecoder {
  public:
    /// @brief Give a human-readable representation of a generic chunk.
    ///
    /// Note: actually implemented in DumperLib.
    friend std::ostream &
    operator<<(std::ostream &ostr, const SCTPGenericChunkDecoder &genericChunk);

    ///@name Constructors
    ///@{

    /// @brief Constructor attaching to the given BufferView.
    SCTPGenericChunkDecoder(const BufferView &dataChunk)
        : mBufferView(dataChunk) {}

    /// @brief Constructor attaching to the given BufferView (moved).
    SCTPGenericChunkDecoder(BufferView &&dataChunk) noexcept
        : mBufferView{std::move(dataChunk)} {}

    /// @brief Default constructor
    ///
    /// @note This allows arrays and other collections of this class.
    SCTPGenericChunkDecoder() = default;

    ///@}

    ///@name Copy semantic
    ///@{
    SCTPGenericChunkDecoder(const SCTPGenericChunkDecoder &) = default;
    SCTPGenericChunkDecoder &
    operator=(const SCTPGenericChunkDecoder &) = default;
    ///@}

    ///@name Move semantic
    ///@{
    SCTPGenericChunkDecoder(SCTPGenericChunkDecoder &&) noexcept = default;
    SCTPGenericChunkDecoder &operator=(SCTPGenericChunkDecoder &&) = default;
    ///@}

    ///@name Read access to a chunk's fields.
    ///@{
    SCTPChunk::Type getType() const {
        return SCTPChunk::Type(mBufferView.getUint8At(typeOffset));
    }

    unsigned char getFlags() const {
        return mBufferView.getUint8At(flagsOffset);
    }

    /// @brief Total chunk length, including header
    std::size_t getTotalLengthBytes() const {
        return mBufferView.getUint16At(lengthOffset);
    }

    ///@}

    ///@name Utilities
    ///@{

    /// @brief True if this is a ```DATA`` SCTP chunk.
    bool isDataChunk() const { return getType() == SCTPChunk::DATA; }

    /// @brief Return the chunk's total length, including headers.
    ///
    /// As this is a generic SCTP chunk decoder, the payload comprises
    /// all the chunk.
    std::size_t getDataLengthBytes() const { return getTotalLengthBytes(); }

    /// @brief Get the whole chunk buffer (including headers).
    ///
    /// As this is a generic SCTP chunk decoder, the payload comprises
    /// all the chunk.
    const BufferView getData() const { return mBufferView; }

    ///@}

  private:
    // Constant offsets, in bytes, of generic header fields
    enum {
        typeOffset = 0,
        flagsOffset = 1,
        lengthOffset = 2,
    };

    // Proper data.
    const BufferView mBufferView;
};

/**
 * @brief Decoding a SCTP ``DATA`` chunk stored in a BufferView.
 */
class SCTPDataChunkDecoder {
  public:
    /// @brief Give a human-readable representation of a SCTP DATA
    ///        chunk.
    ///
    /// Note: actually implemented in DumperLib.
    friend std::ostream &operator<<(std::ostream &ostr,
                                    const SCTPDataChunkDecoder &d);

    ///@name Constructors
    ///@{

    /// @brief Constructor attaching to the given BufferView.
    SCTPDataChunkDecoder(const BufferView &dataChunk)
        : mBufferView(dataChunk) {}

    /// @brief Constructor attaching to the given BufferView (moved)
    SCTPDataChunkDecoder(BufferView &&dataChunk) noexcept
        : mBufferView{std::move(dataChunk)} {}

    ///@}

    ///@name No default constructor
    ///@{
    SCTPDataChunkDecoder() = delete;
    ///@}

    ///@name No copy semantic
    ///@{
    SCTPDataChunkDecoder(const SCTPDataChunkDecoder &) = delete;
    SCTPDataChunkDecoder &operator=(const SCTPDataChunkDecoder &) = delete;
    ///@}

    ///@name No move semantic
    ///@{
    SCTPDataChunkDecoder(SCTPDataChunkDecoder &&) noexcept = delete;
    SCTPDataChunkDecoder &operator=(SCTPDataChunkDecoder &&) = delete;
    ///@}

    ///@name Read access to SCTP DATA chunk header fields
    ///@{

    SCTPChunk::Type getType() const {
        return SCTPChunk::Type(mBufferView.getUint8At(typeOffset));
    }

    /// @brief Return total chunk length, including header
    std::size_t getTotalLengthBytes() const {
        return mBufferView.getUint16At(lengthOffset);
    }

    bool getFlagI() const {
        return (((mBufferView.getUint8At(flagsOffset)) >> 3) & 1);
    }

    bool getFlagU() const {
        return (((mBufferView.getUint8At(flagsOffset)) >> 2) & 1);
    }

    bool getFlagB() const {
        return (((mBufferView.getUint8At(flagsOffset)) >> 1) & 1);
    }

    bool getFlagE() const { return (mBufferView.getUint8At(flagsOffset)) & 1; }

    std::uint32_t getTSN() const { return mBufferView.getUint32At(tsnOffset); }

    std::uint16_t getStreamIdentifier() const {
        return mBufferView.getUint16At(streamIdentifierOffset);
    }

    std::uint16_t getStreamSequenceNumber() const {
        return mBufferView.getUint16At(streamSequenceNumberOffset);
    }

    std::uint32_t getPayloadProtocolIdentifier() const {
        return mBufferView.getUint32At(payloadProtocolIdentifierOffset);
    }

    ///@}

    ///@name Utilities
    ///@{

    /// @brief Get chunk payload length, in bytes.
    std::size_t getDataLengthBytes() const {
        return getTotalLengthBytes() - dataOffset;
    }

    /// @brief Return a BufferView with the chunk payload.
    const BufferView getData() const {
        return mBufferView.getSub(dataOffset, getDataLengthBytes());
    }

    /// @brief True when this is a fragmented SCTP message.
    bool isAFragment() const {
        // It is a fragment, unless both B and E flags are set.
        return !(getFlagB() && getFlagE());
    }

    /// @brief True when this is a S1AP chunk.
    ///
    /// (see
    /// https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25
    /// and also 3GPP TS 36.412 sect. 7)
    bool isS1AP() const { return getPayloadProtocolIdentifier() == 0x12; }

    ///@}

  private:
    // Constant offsets, in bytes, of header fields
    enum {
        typeOffset = 0,
        flagsOffset = 1,
        lengthOffset = 2,
        tsnOffset = 4,
        streamIdentifierOffset = 8,
        streamSequenceNumberOffset = 10,
        payloadProtocolIdentifierOffset = 12,
    };

    // Offsets of data fields
    enum {
        dataOffset = 16,
    };

    // Proper data.
    const BufferView mBufferView;
};

/**
 * @brief Decode a (whole) SCTP packet stored in a BufferView.
 *
 * In particular, it provides easy access to SCTP chunks.
 */
class SCTPDecoder {
  public:
    /// @brief Type for a collection of chunk decoders.
    using ChunksVector = std::vector<SCTPGenericChunkDecoder>;

    ///@name Constructors
    ///@{

    /// @brief Constructor attaching to the given BufferView.
    ///
    /// Throws exceptions if the BufferView is unsuitable (empty, too
    /// short, etc.).
    SCTPDecoder(const BufferView &sctpData) : mBufferView(sctpData) {
        throwIfBufferIsUnsuitable(
            NETWORKLIB_CURRENT_FUNCTION);
        fillChunksVector();
    }

    /// @brief Constructor attaching to the given BufferView (moved).
    ///
    /// Throws exceptions if the BufferView is unsuitable (empty, too
    /// short, etc.).
    SCTPDecoder(BufferView &&sctpData) : mBufferView{std::move(sctpData)} {
        throwIfBufferIsUnsuitable(NETWORKLIB_CURRENT_FUNCTION);
        fillChunksVector();
    }

    ///@}

    ///@name No default constructor
    ///@{
    SCTPDecoder() = delete;
    ///@}

    ///@name No copy semantic
    ///@{
    SCTPDecoder(const SCTPDecoder &) = delete;
    SCTPDecoder &operator=(const SCTPDecoder &) = delete;
    ///@}

    ///@name No move semantic
    ///@{
    SCTPDecoder(SCTPDecoder &&) = delete;
    SCTPDecoder &operator=(SCTPDecoder &&) = delete;
    ///@}

    ///@name Read access to SCTP header fields
    ///@{

    Port::Number getSrcPort() const {
        // Bounds already checked on construction
        return Port::Number(mBufferView.getUint16At_nocheck(srcPortOffset));
    }

    Port::Number getDstPort() const {
        // Bounds already checked on construction
        return Port::Number(mBufferView.getUint16At_nocheck(dstPortOffset));
    }

    std::uint32_t getVerificationTag() const {
        // Bounds already checked on construction
        return mBufferView.getUint32At_nocheck(verificationTagOffset);
    }

    std::uint32_t getChecksum() const {
        // Bounds already checked on construction
        return mBufferView.getUint32At_nocheck(checksumOffset);
    }

    ///@}

    ///@name Utilities
    ///@{

    /// @brief Get the SCTP chunks in this packet
    const ChunksVector &chunks() const { return mChunks; }

    ///@}

  private:
    // Constant offsets, in bytes, of header fields
    enum {
        srcPortOffset = 0,
        dstPortOffset = 2,
        verificationTagOffset = 4,
        checksumOffset = 8,
    };

    // Offsets of data fields
    enum {
        startOfChunksOffset = 12,
    };

    // Constant offsets inside a chunk
    enum {
        chunkLengthOffset = 2,
    };

    // Proper data.
    const BufferView mBufferView;

    // A std::vector SCTPGenericChunkDecoder pointing
    // to the chunks of this SCTP packet
    // (filled by fillChunksVector() on construction)
    ChunksVector mChunks;

    // Helper method filling the chunks vector on construction
    void fillChunksVector();

    void throwIfBufferIsUnsuitable(const char *method) {
        // Catch some quirks early
        if (mBufferView.size() < 12) {
            std::ostringstream err;
            err << method
                << ": called with "
                   "BufferView.size() == "
                << mBufferView.size() << " (min size is 12)";
            throw std::length_error(err.str());
        }
    }
};
} // namespace NetworkLib
} // namespace UPF

#endif
