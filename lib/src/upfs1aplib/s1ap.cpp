#include <upfs1aplib/s1aplib.hh>

// For std::memset()
//#include <cstring>

// For std::runtime_error
#include <stdexcept>

// For std::ostringstream
#include <sstream>

// For ASN1Lib definitions of S1AP structures.
extern "C" {
#include <S1AP_S1AP-PDU.h>
#include <asn_application.h>
}

namespace UPF {
namespace S1APLib {
S1APDecoder::S1APDecoder(const NetworkLib::BufferView &s1apData)
    : mBufferView(s1apData), mPDU(nullptr) {
    asn_dec_rval_t decodeRC = {RC_OK, 0};

    // Try to decode the buffer
    decodeRC = aper_decode(
        NULL, &asn_DEF_S1AP_S1AP_PDU, reinterpret_cast<void **>(&(mPDU)),
        mBufferView.getUnderlyingBufferPtr(), mBufferView.size(), 0, 0);

    if (decodeRC.code != RC_OK) {
        if (mPDU != nullptr) {
            // Free partially-filled decoded PDU
            ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, mPDU);
            mPDU = nullptr;
        }

        std::ostringstream err;
        err << NETWORKLIB_CURRENT_FUNCTION << ": error decoding S1AP PDU";
        throw std::runtime_error(err.str());
    }
}

S1APDecoder::~S1APDecoder() {
    if (mPDU != nullptr) {
        // Free decoded PDU
        ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, mPDU);
        mPDU = nullptr;
    }
}

} // namespace S1APLib
} // namespace UPF
