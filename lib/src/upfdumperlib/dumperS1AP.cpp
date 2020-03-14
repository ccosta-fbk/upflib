#include <upfdumperlib/dumper.hh>
#include <upfs1aplib/s1aplib.hh>

// For std::hex and such
#include <iomanip>

// For std::ostream
#include <ostream>

// For ASN1Lib definitions of S1AP structures.
extern "C" {
#include <S1AP_S1AP-PDU.h>
#include <asn_application.h>
}

namespace UPF {
namespace S1APLib {
// Helper function
static int printBufferToOstream(const void *buffer, size_t size,
                                void *application_specific_key) {
    std::ostream &ostr =
        *(reinterpret_cast<std::ostream *>(application_specific_key));
    ostr.write(static_cast<const char *>(buffer), size);
    return 0;
}

std::ostream &operator<<(std::ostream &ostr, const S1APDecoder &d) {

    asn_enc_rval_t rc;

    rc = xer_encode(&asn_DEF_S1AP_S1AP_PDU, &d.getS1AP_PDU(), XER_F_BASIC,
                    printBufferToOstream, static_cast<void *>(&ostr));

    return ostr;
}
} // namespace S1APLib
} // namespace UPF
