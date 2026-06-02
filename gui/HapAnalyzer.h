#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>

// Opaque handle
typedef struct HapAnalyzerCtx HapAnalyzerCtx;

HapAnalyzerCtx* hap_analyzer_create(void);
void hap_analyzer_destroy(HapAnalyzerCtx* ctx);
int hap_analyzer_load(HapAnalyzerCtx* ctx, const char* path);

// Query
int64_t hap_get_file_count(HapAnalyzerCtx* ctx);
int64_t hap_get_file_size(HapAnalyzerCtx* ctx);
const char* hap_get_filename(int64_t index, HapAnalyzerCtx* ctx);
int64_t hap_get_file_size_at(int64_t index, HapAnalyzerCtx* ctx);
const char* hap_get_file_sha256(int64_t index, HapAnalyzerCtx* ctx);

int hap_get_cert_chain_count(HapAnalyzerCtx* ctx);
int hap_get_cert_count(int chainIdx, HapAnalyzerCtx* ctx);
const char* hap_get_cert_subject(int chainIdx, int certIdx, HapAnalyzerCtx* ctx);
const char* hap_get_cert_issuer(int chainIdx, int certIdx, HapAnalyzerCtx* ctx);
const char* hap_get_cert_sha256(int chainIdx, int certIdx, HapAnalyzerCtx* ctx);
const char* hap_get_cert_key_info(int chainIdx, int certIdx, HapAnalyzerCtx* ctx);
const char* hap_get_cert_validity(int chainIdx, int certIdx, HapAnalyzerCtx* ctx);
int hap_get_cert_is_valid(int chainIdx, int certIdx, HapAnalyzerCtx* ctx);
int hap_get_chain_content_ok(int chainIdx, HapAnalyzerCtx* ctx);
int hap_get_identity_chain_count(HapAnalyzerCtx* ctx);
const char* hap_get_identity_cert_subject(int idx, HapAnalyzerCtx* ctx);
const char* hap_get_identity_cert_sha256(int idx, HapAnalyzerCtx* ctx);
const char* hap_get_identity_cert_key_info(int idx, HapAnalyzerCtx* ctx);
const char* hap_get_identity_cert_validity(int idx, HapAnalyzerCtx* ctx);
int hap_get_identity_cert_is_valid(int idx, HapAnalyzerCtx* ctx);
int hap_get_identity_verified(HapAnalyzerCtx* ctx);
int hap_get_chain_block_count(HapAnalyzerCtx* ctx);
int hap_get_chain_version(HapAnalyzerCtx* ctx);

const char* hap_get_profile_field(const char* field, HapAnalyzerCtx* ctx);
int hap_has_code_sign(HapAnalyzerCtx* ctx);
int hap_get_code_sign_lib_count(HapAnalyzerCtx* ctx);
const char* hap_get_code_sign_lib(int index, HapAnalyzerCtx* ctx);

int hap_get_subblock_count(HapAnalyzerCtx* ctx);
uint32_t hap_get_subblock_type(int index, HapAnalyzerCtx* ctx);
int64_t hap_get_subblock_offset(int index, HapAnalyzerCtx* ctx);
int64_t hap_get_subblock_length(int index, HapAnalyzerCtx* ctx);

const char* hap_get_verdict(HapAnalyzerCtx* ctx);
const char* hap_get_verdict_summary(HapAnalyzerCtx* ctx);

#ifdef __cplusplus
}
#endif
