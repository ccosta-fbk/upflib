/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "3GPP_TS_36.413_v14.4.0.asn"
 * 	`asn1c -S /home/daigodevel/GIT3/brchiu-asn1c/skeletons -pdu=all -fcompound-names -findirect-choice -fno-include-deps -gen-PER`
 */

#ifndef	_S1AP_M3period_H_
#define	_S1AP_M3period_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum S1AP_M3period {
	S1AP_M3period_ms100	= 0,
	S1AP_M3period_ms1000	= 1,
	S1AP_M3period_ms10000	= 2
	/*
	 * Enumeration is extensible
	 */
} e_S1AP_M3period;

/* S1AP_M3period */
typedef long	 S1AP_M3period_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_S1AP_M3period_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_S1AP_M3period;
extern const asn_INTEGER_specifics_t asn_SPC_S1AP_M3period_specs_1;
asn_struct_free_f S1AP_M3period_free;
asn_struct_print_f S1AP_M3period_print;
asn_constr_check_f S1AP_M3period_constraint;
ber_type_decoder_f S1AP_M3period_decode_ber;
der_type_encoder_f S1AP_M3period_encode_der;
xer_type_decoder_f S1AP_M3period_decode_xer;
xer_type_encoder_f S1AP_M3period_encode_xer;
oer_type_decoder_f S1AP_M3period_decode_oer;
oer_type_encoder_f S1AP_M3period_encode_oer;
per_type_decoder_f S1AP_M3period_decode_uper;
per_type_encoder_f S1AP_M3period_encode_uper;
per_type_decoder_f S1AP_M3period_decode_aper;
per_type_encoder_f S1AP_M3period_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _S1AP_M3period_H_ */
#include <asn_internal.h>