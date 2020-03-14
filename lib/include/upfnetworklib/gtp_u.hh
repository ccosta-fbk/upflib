#ifndef UPFNETWORKLIB_GTPU_HH
#define UPFNETWORKLIB_GTPU_HH

#include <upfnetworklib/utils.hh>

// For BufferView
#include <upfnetworklib/buffers.hh>

// For Port
#include <upfnetworklib/ipv4.hh>

// For std::vector
#include <vector>

// For std::size_t
#include <cstddef>

// For std::uintXX_t
#include <cstdint>

// For operator<<() overload
#include <sstream>

namespace UPF {
namespace NetworkLib {

/// @brief A namespace for GTP TEIDs.
namespace GTP_TEID {
/// @brief A type representing a GTPv1-U TEID.
///
/// Note: from 3GPP TS 36.413 v14.4.0 we have the following ASN.1 type
///
///     GTP-TEID ::= OCTET STRING (SIZE (4))
///
/// Basically, four 8-bit bytes. Fits nicely in a ``std::uint32_t``.
///
enum Number : std::uint32_t {
    Invalid = 0,
    Unspecified = 0,
};
} // namespace GTP_TEID

/// @brief A GTPv1-U tunnel endpoint.
///
/// A GTPv1-U endpoint is identified by the tuple ``(address, port, TEID)``.
/// In practice, the port is usually the default one (2152).
struct GTPv1UEndPoint {
    /// @brief IPv4 address of the endpoint.
    IPv4Address ipAddress;

    /// @brief UDP port of the endpoint.
    Port::Number port = Port::Unspecified;

    /// @brief TEID of the endpoint.
    GTP_TEID::Number teid = GTP_TEID::Unspecified;
};

/**
 * @brief Decode a GTPv1-U packet stored in a BufferView.
 */
class GTPv1UDecoder {
  public:
    ///@name Constructors

    /// @brief Constructor attaching to the given BufferView.
    ///
    /// Throws exceptions if the BufferView is unsuitable (empty, too
    /// short, etc.).
    GTPv1UDecoder(const BufferView &gtpuData) : mBufferView(gtpuData) {
        throwIfBufferIsUnsuitable(
            NETWORKLIB_CURRENT_FUNCTION);
        extractExtensionHeadersAndFindPayload();
    }

    /// @brief Constructor attaching to the given BufferView (moved).
    ///
    /// Throws exceptions if the BufferView is unsuitable (empty, too
    /// short, etc.).
    GTPv1UDecoder(BufferView &&gtpuData) : mBufferView{std::move(gtpuData)} {
        throwIfBufferIsUnsuitable(NETWORKLIB_CURRENT_FUNCTION);
        extractExtensionHeadersAndFindPayload();
    }

    ///@}

    ///@name No default constructor
    ///@{
    GTPv1UDecoder() = delete;
    ///@}

    ///@name No copy semantic
    ///@{
    GTPv1UDecoder(const GTPv1UDecoder &) = delete;
    GTPv1UDecoder &operator=(const GTPv1UDecoder &) = delete;
    ///@}

    ///@name No move semantic
    ///@{
    GTPv1UDecoder(GTPv1UDecoder &&) = delete;
    GTPv1UDecoder &operator=(GTPv1UDecoder &&) = delete;
    ///@}

    ///@name Read access to **mandatory** GTPv1-U header fields
    ///@{

    unsigned char getVersion() const {
        // Bounds already checked on construction
        return (mBufferView.getUint8At_nocheck(0) >> 5) & 0x07;
    }

    unsigned char getProtocolType() const {
        // Bounds already checked on construction
        return ((mBufferView.getUint8At_nocheck(0) & 0x10) != 0) ? 1 : 0;
    }

    bool hasNextExtensionField() const {
        // Bounds already checked on construction
        return ((mBufferView.getUint8At_nocheck(0) & 0x04) != 0);
    }

    bool hasSequenceNumberField() const {
        // Bounds already checked on construction
        return ((mBufferView.getUint8At_nocheck(0) & 0x02) != 0);
    }

    bool hasNPDUField() const {
        // Bounds already checked on construction
        return ((mBufferView.getUint8At_nocheck(0) & 0x01) != 0);
    }

    unsigned char getMessageType() const {
        // Bounds already checked on construction
        return mBufferView.getUint8At_nocheck(messageTypeOffset);
    }

    std::uint16_t getMessageLength() const {
        // Bounds already checked on construction
        return mBufferView.getUint16At_nocheck(messageLengthOffset);
    }

    GTP_TEID::Number getTEID() const {
        // Bounds already checked on construction
        return GTP_TEID::Number(mBufferView.getUint32At_nocheck(teidOffset));
    }

    ///@}

    ///@name Read access to **optional** GTPv1-U header fields
    ///@{

    std::uint16_t getSequenceNumber() const {
        // Return the field actual value only if the corresponding
        // flag tells that the value is there and is significant.
        return hasSequenceNumberField()
                   ? mBufferView.getUint16At(sequenceNumberOffset)
                   : 0;
    }

    unsigned char getNPDUNumber() const {
        // Return the field actual value only if the corresponding
        // flag tells that the value is there and is significant.
        return hasNPDUField() ? mBufferView.getUint8At(npduNumberOffset) : 0;
    }

    unsigned char getFirstNextExtensionType() const {
        // Return the field actual value only if the corresponding
        // flag tells that the value is there and is significant.
        return hasNextExtensionField()
                   ? mBufferView.getUint8At(nextExtensionTypeOffset)
                   : 0;
    }

    ///@}

    ///@name Utilities
    ///@{

    /// @brief Tells if there are any extra optional fields right
    ///        after the common header (4 extra bytes in total).
    ///
    /// Note that the mere presence of such extra fields does NOT
    /// imply they should be considered: an optional field has to be
    /// considered iff its corrsponding flag in the common header
    /// tells that its value is significative -- otherwise it should
    /// be ignored.
    bool hasOptionalFields() const {
        // Brief version. It's logically equivalent to
        // (hasSequenceNumberField() || hasNPDUField() ||
        // hasNextExtensionField())
        return (mBufferView.getUint8At(0) & 0x03) != 0;
    }

    /// @brief Get the payload length, in bytes
    std::size_t getDataLengthBytes() const { return mDataLengthBytes; }

    /// @brief Return a BufferView with the payload.
    BufferView getData() const {
        return mBufferView.getSub(mDataOffset, mDataLengthBytes);
    }

    /// @brief Read access to the portions of the buffer storing the
    ///        Extension Headers in this packet, if any.
    ///
    /// Note that the first byte of each portion tells the extension
    /// header type, followed by the actual extension header, and
    /// without the finale 'next extension header' byte (see comments
    /// about 'mExtensionHeaders').
    const std::vector<BufferView> &getExtensionHeaders() const {
        return mExtensionHeaders;
    }

    /// @brief True if the payload is a IPv4 packet/fragment.
    bool isIPv4PDU() const { return getMessageType() == 0xFF; }

    ///@}

  private:
    // Constant offsets, in bytes, of common header fields
    enum {
        messageTypeOffset = 1,
        messageLengthOffset = 2,
        teidOffset = 4,
    };

    // Constant offsets, in bytes, of optional header fields
    enum {
        sequenceNumberOffset = 8,
        npduNumberOffset = 10,
        nextExtensionTypeOffset = 11,
    };

    // Other offsets
    enum {
        endOfCommonHeaderOffset = 8,
        endOfOptionalFieldsOffset = 11,
    };

    // Proper data.
    BufferView mBufferView;

    // A vector pointing to each Extension header, if any.
    //
    // In order to keep things sane, Extention headers are stored
    // differently from what could be expected: the first byte is not
    // the one of the extension header itself, but it is the last one
    // of the previous header, telling which is the type of the
    // following header.
    //
    // This way the whole can be treated just as a plain, old,
    // Type-Length-Value entry (with "length" that is is multples of 4
    // bytes).
    //
    // This also means that the offset to the start of a Extension
    // header is *not* aligned to 4 bytes, and that you won't find
    // a "next Extention header type" byte at the end of a header.
    //
    // +-------------+-----------+----------+
    // |       0     |    1      |    2...  |
    // +-------------+-----------+----------+
    // | Next ext.   | Extension | Contents |
    // | header type | Length    | ...      |
    // +-------------+-----------+----------+
    //
    std::vector<BufferView> mExtensionHeaders;

    // In GTP1-U the payload starts after the common header,
    // after the optional fields of the common header, and
    // after any extension header.
    mutable std::size_t mDataOffset;
    mutable std::size_t mDataLengthBytes;

    // Helper method
    void extractExtensionHeadersAndFindPayload() {
        std::size_t offset = endOfCommonHeaderOffset;

        if (hasOptionalFields()) {
            // Skip optional fields.
            offset = endOfOptionalFieldsOffset;

            if (hasNextExtensionField()) {

                // Ok there could be zero or more extension headers at
                // this offset.
                //
                // Let's look at the 'Next Extension Header Field
                // value': as for 3GPP TS 29.060 sect. 6, a value of 0
                // means 'No more extension headers'.
                while (mBufferView.getUint8At(offset) != 0) {
                    // There's an extension header at this offset

                    // As for 3GPP TS 29.060 sec. 6:
                    //
                    // | The length of the Extension header shall be
                    // | defined in a variable length of 4 octets,
                    // | i.e. m+1 = n*4 octets, where n is a positive
                    // | integer.
                    const std::size_t extLen =
                        4 * mBufferView.getUint8At(offset + 1);

                    mExtensionHeaders.push_back(
                        mBufferView.getSub(offset, extLen));
                    offset += extLen;
                }
            }
        }

        // At this point, 'offset' is at the start of the payload.
        mDataOffset = offset;

        // The message length field includes everything after the
        // common header (8 bytes), including the optional fields if
        // any (4 bytes) and any extension headers.
        //
        // The payload length is therefore the 'message length' field
        // minus the offset to the payload start, plus the 8 bytes of
        // the common header.
        //
        mDataLengthBytes =
            getMessageLength() - offset + endOfCommonHeaderOffset;
    }

    void throwIfBufferIsUnsuitable(const char *method) {

        // Catch some quirks early
        if (mBufferView.size() < 8) {
            std::ostringstream err;
            err << method
                << ": called with "
                   "BufferView.size() == "
                << mBufferView.size() << " (min size is 8)";
            throw std::length_error(err.str());
        }

        const std::uint8_t protocolAndVersion =
            mBufferView.getUint8At_nocheck(0) >> 4;

        if (protocolAndVersion != 0x03) {
            // 0x03 means GTPv1
            std::ostringstream err;
            err << method << ": not GTPv1 data (protocol+version is "
                << asHex8(protocolAndVersion) << ", expected 0x03)";
            throw std::runtime_error(err.str());
        }
    }
};
} // namespace NetworkLib
} // namespace UPF

#endif
