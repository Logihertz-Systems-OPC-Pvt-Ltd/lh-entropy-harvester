#ifndef LH_ENTROPY_TYPES_H
#define LH_ENTROPY_TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define LH_ENT_MAX_RULES 10
#define LH_ENT_MAX_NAME_LEN 64
#define LH_ENT_MAX_DESC_LEN 256
#define LH_ENT_APT_WINDOW_SIZE 512
#define LH_ENT_SHA256_DIGEST_SIZE 32
#define LH_ENT_MAX_NOISE_SAMPLES 65536

/* Linux ioctl /dev/random injection command */
#ifndef RNDADDENTROPY
#define RNDADDENTROPY 0x40085203
#endif

/* Severity Levels for Posture Auditor */
typedef enum {
    SEV_INFO = 0,
    SEV_LOW = 1,
    SEV_MEDIUM = 4,
    SEV_HIGH = 10,
    SEV_CRITICAL = 25
} severity_t;

/* Continuous Health Fault Flags */
typedef enum {
    ENTROPY_FAULT_NONE = 0,
    ENTROPY_FAULT_RCT_STUCK_AT = (1 << 0),
    ENTROPY_FAULT_APT_STATISTICAL_BIAS = (1 << 1),
    ENTROPY_FAULT_LOW_MIN_ENTROPY = (1 << 2),
    ENTROPY_FAULT_AUTOCORRELATION_HARMONIC = (1 << 3),
    ENTROPY_FAULT_RAIL_SATURATION = (1 << 4)
} entropy_fault_t;

/* Repetition Count Test (RCT) State - NIST SP 800-90B Sec 4.4.1 */
typedef struct {
    uint8_t last_sample;
    uint32_t current_run;
    uint32_t cutoff_c_rct;
    double assessed_h_min;
    bool fault_latched;
    uint64_t total_samples_tested;
    uint64_t stuck_at_fault_count;
} rct_state_t;

/* Adaptive Proportion Test (APT) State - NIST SP 800-90B Sec 4.4.2 */
typedef struct {
    uint32_t window_size;
    uint32_t current_window_index;
    uint8_t target_symbol;
    uint32_t target_count;
    uint32_t cutoff_c_apt;
    double assessed_h_min;
    bool fault_latched;
    uint64_t total_windows_tested;
    uint64_t bias_fault_count;
} apt_state_t;

/* Combined Continuous Health Tester State */
typedef struct {
    rct_state_t rct;
    apt_state_t apt;
    uint32_t fault_flags;
    bool halt_on_fault;
} sp800_90b_health_t;

/* Raw Noise Analysis Summary */
typedef struct {
    uint32_t sample_count;
    double shannon_entropy_h1;         /* H_1 bits/byte */
    double mcv_min_entropy_h_inf;      /* H_inf bits/byte */
    double mcv_min_entropy_per_bit;    /* bits/bit */
    double most_probable_p_max;        /* p_max */
    double upper_bound_p_u;            /* p_u with 99% confidence */
    double lag1_autocorrelation_r1;    /* Pearson r_1 */
    uint32_t rct_cutoff;
    uint32_t apt_cutoff;
    bool rct_passed;
    bool apt_passed;
    bool harmonic_coupling_detected;   /* |r_1| > 0.15 */
    bool rail_saturation_detected;     /* 0x00 or 0xFF excessive */
    char verdict[LH_ENT_MAX_NAME_LEN];
} noise_analysis_result_t;

/* Linux Kernel RNDADDENTROPY Payload */
struct rand_pool_info {
    int entropy_count;
    int buf_size;
    uint32_t buf[8]; /* 32 bytes (256 bits) */
};

/* Conditioned Entropy Block Output */
typedef struct {
    uint8_t digest[LH_ENT_SHA256_DIGEST_SIZE];
    uint32_t raw_bytes_consumed;
    int credited_entropy_bits;
    struct rand_pool_info pool_info;
} conditioned_block_t;

/* TRNG Daemon Security Policy Configuration */
typedef struct {
    char policy_name[LH_ENT_MAX_NAME_LEN];
    double min_entropy_bits_per_byte;
    uint32_t noise_source_count;
    char cryptographic_conditioner[32];
    double compression_ratio;
    bool rct_enabled;
    bool apt_enabled;
    bool halt_feed_on_health_fault;
    uint32_t startup_conditioning_samples;
    double entropy_credit_derating_factor;
    bool credit_full_raw_bitcount;
    bool mlockall_enabled;
    bool zeroize_buffers_after_feed;
    bool adc_rail_saturation_guard;
    double max_serial_autocorrelation;
    bool drop_privileges_cap_sys_admin_only;
    bool seccomp_syscall_filter;
    uint32_t write_wakeup_threshold_bits;
    uint32_t max_reseed_interval_sec;
    bool conditioner_startup_kat_verified;
    bool log_health_test_failures;
} entropy_policy_t;

/* Individual Rule Finding */
typedef struct {
    char rule_id[16];
    char rule_name[LH_ENT_MAX_NAME_LEN];
    char cwe_id[16];
    severity_t severity;
    uint32_t deduction;
    bool passed;
    char details[LH_ENT_MAX_DESC_LEN];
    char recommendation[LH_ENT_MAX_DESC_LEN];
} audit_finding_t;

/* Complete Audit Report */
typedef struct {
    char policy_name[LH_ENT_MAX_NAME_LEN];
    uint32_t total_rules;
    uint32_t passed_rules;
    uint32_t failed_rules;
    uint32_t total_deductions;
    uint32_t posture_score;
    audit_finding_t findings[LH_ENT_MAX_RULES];
} audit_report_t;

/* Raw Sample Buffer */
typedef struct {
    uint32_t count;
    uint8_t samples[LH_ENT_MAX_NOISE_SAMPLES];
} raw_noise_buffer_t;

#endif /* LH_ENTROPY_TYPES_H */
