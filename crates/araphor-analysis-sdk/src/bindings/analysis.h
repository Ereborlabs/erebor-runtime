#ifndef ARAPHOR_ANALYSIS_V1_H
#define ARAPHOR_ANALYSIS_V1_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ARAPHOR_ANALYSIS_CONTRACT_VERSION 1u

struct ArrowArrayStream;

typedef struct {
    const uint8_t *data;
    uint64_t size;
} araphor_analysis_bytes_v1;

typedef struct {
    uint32_t max_batches;
    uint64_t max_rows;
    uint64_t max_bytes;
    uint64_t max_checkpoint_bytes;
} araphor_analysis_limits_v1;

typedef struct {
    araphor_analysis_bytes_v1 id;
    int64_t time_utc_ns;
    uint64_t seed;
    uint8_t has_seed;
    araphor_analysis_limits_v1 limits;
} araphor_analysis_context_v1;

typedef struct {
    araphor_analysis_bytes_v1 source;
    int64_t start_utc_ns;
    int64_t end_utc_ns;
} araphor_analysis_window_v1;

typedef struct {
    araphor_analysis_bytes_v1 owner;
    araphor_analysis_bytes_v1 id;
    const araphor_analysis_window_v1 *window;
} araphor_analysis_revision_v1;

typedef enum {
    ARAPHOR_ANALYSIS_COMPLETE = 0,
    ARAPHOR_ANALYSIS_GAPPED = 1,
    ARAPHOR_ANALYSIS_UNKNOWN = 2
} araphor_analysis_coverage_state_v1;

typedef struct {
    uint32_t state;
    const araphor_analysis_bytes_v1 *limits;
    uint64_t limit_count;
} araphor_analysis_coverage_v1;

/* Each stream uses the exact Arrow schema in the package descriptor. */
typedef struct {
    araphor_analysis_bytes_v1 name;
    struct ArrowArrayStream *batches;
} araphor_analysis_dataset_v1;

typedef struct {
    araphor_analysis_dataset_v1 data;
    araphor_analysis_revision_v1 revision;
    araphor_analysis_coverage_v1 coverage;
} araphor_analysis_input_v1;

typedef struct {
    uint32_t version;
    const araphor_analysis_dataset_v1 *datasets;
    uint64_t dataset_count;
} araphor_analysis_checkpoint_v1;

typedef struct {
    araphor_analysis_bytes_v1 dataset;
    uint64_t row;
} araphor_analysis_row_ref_v1;

typedef struct {
    araphor_analysis_row_ref_v1 output;
    araphor_analysis_row_ref_v1 input;
} araphor_analysis_evidence_link_v1;

typedef struct {
    araphor_analysis_row_ref_v1 output;
    araphor_analysis_bytes_v1 code;
    struct ArrowArrayStream *details;
} araphor_analysis_reason_value_v1;

typedef enum {
    ARAPHOR_ANALYSIS_OK = 0,
    ARAPHOR_ANALYSIS_INVALID = 1,
    ARAPHOR_ANALYSIS_INCOMPATIBLE = 2,
    ARAPHOR_ANALYSIS_UNAUTHORIZED = 3,
    ARAPHOR_ANALYSIS_INCOMPLETE = 4,
    ARAPHOR_ANALYSIS_FAILED = 5,
    ARAPHOR_ANALYSIS_LIMIT = 6
} araphor_analysis_error_code_v1;

typedef struct {
    uint32_t code;
    araphor_analysis_bytes_v1 field;
} araphor_analysis_error_v1;

typedef struct {
    araphor_analysis_bytes_v1 export_name;
    const araphor_analysis_input_v1 *inputs;
    uint64_t input_count;
    struct ArrowArrayStream *parameters;
    araphor_analysis_context_v1 context;
    const araphor_analysis_checkpoint_v1 *checkpoint;
    int32_t (*cancelled)(void *context);
    void *cancel_context;
} araphor_analysis_request_v1;

typedef struct {
    const araphor_analysis_dataset_v1 *datasets;
    uint64_t dataset_count;
    const araphor_analysis_evidence_link_v1 *evidence;
    uint64_t evidence_count;
    const araphor_analysis_reason_value_v1 *reasons;
    uint64_t reason_count;
    const araphor_analysis_checkpoint_v1 *checkpoint;
    araphor_analysis_error_v1 error;
    void *private_data;
} araphor_analysis_response_v1;

/* Request data stays borrowed until evaluate returns. Strings use UTF-8. */
/* The callee reads request streams and does not release these streams. */
/* Response values must not borrow request storage. */
/* The parameter pointer is null only when its declared schema is empty. */
/* Each parameter stream and reason detail stream contains exactly one row. */
/* Zero the response before each call. Release the response after every call. */
/* Consumers release each received Arrow array before they release the response. */
/* The producer releases unread output streams and all response buffers. */
/* Release clears owned fields. A second release does not change state. */
/* A nonzero cancellation result requires an incomplete result. */
/* Pointers stay inside one worker process. */
/* Panics and exceptions must not cross this boundary. */
typedef struct {
    uint32_t contract_version;
    uint64_t struct_size;
    uint32_t (*evaluate)(const araphor_analysis_request_v1 *request,
                         araphor_analysis_response_v1 *response);
    void (*release)(araphor_analysis_response_v1 *response);
} araphor_analysis_api_v1;

#ifdef __cplusplus
}
#endif

#endif
