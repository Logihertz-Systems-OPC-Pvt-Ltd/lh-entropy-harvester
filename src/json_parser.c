#include "json_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void skip_ws(const char **p) {
    while (**p && (isspace((unsigned char)**p) || **p == ',' || **p == ':')) {
        (*p)++;
    }
}

static const char *find_json_key(const char *json, const char *key) {
    if (!json || !key) return NULL;
    char search_buf[128];
    snprintf(search_buf, sizeof(search_buf), "\"%s\"", key);

    const char *pos = strstr(json, search_buf);
    while (pos) {
        const char *after = pos + strlen(search_buf);
        while (*after && isspace((unsigned char)*after)) after++;
        if (*after == ':') {
            after++;
            while (*after && isspace((unsigned char)*after)) after++;
            return after;
        }
        pos = strstr(pos + 1, search_buf);
    }
    return NULL;
}

static int parse_string_val(const char *val_pos, char *out, size_t max_len) {
    if (!val_pos || !out || max_len == 0) return -1;
    skip_ws(&val_pos);
    if (*val_pos != '"') return -1;
    val_pos++;

    size_t i = 0;
    while (*val_pos && *val_pos != '"' && i + 1 < max_len) {
        if (*val_pos == '\\' && *(val_pos + 1)) {
            val_pos++;
        }
        out[i++] = *val_pos++;
    }
    out[i] = '\0';
    return 0;
}

static int parse_bool_val(const char *val_pos, bool *out) {
    if (!val_pos || !out) return -1;
    skip_ws(&val_pos);
    if (strncmp(val_pos, "true", 4) == 0) {
        *out = true;
        return 0;
    }
    if (strncmp(val_pos, "false", 5) == 0) {
        *out = false;
        return 0;
    }
    return -1;
}

static int parse_int_val(const char *val_pos, int64_t *out) {
    if (!val_pos || !out) return -1;
    skip_ws(&val_pos);
    char *endp = NULL;
    long long v = strtoll(val_pos, &endp, 10);
    if (endp == val_pos) return -1;
    *out = (int64_t)v;
    return 0;
}

static int parse_double_val(const char *val_pos, double *out) {
    if (!val_pos || !out) return -1;
    skip_ws(&val_pos);
    char *endp = NULL;
    double v = strtod(val_pos, &endp);
    if (endp == val_pos) return -1;
    *out = v;
    return 0;
}

int parse_entropy_policy_json(const char *json_str, entropy_policy_t *policy) {
    if (!json_str || !policy) return -1;
    memset(policy, 0, sizeof(entropy_policy_t));

    const char *pos = NULL;

    pos = find_json_key(json_str, "policy_name");
    if (pos) parse_string_val(pos, policy->policy_name, sizeof(policy->policy_name));
    else snprintf(policy->policy_name, sizeof(policy->policy_name), "default_entropy_policy");

    pos = find_json_key(json_str, "min_entropy_bits_per_byte");
    if (pos) parse_double_val(pos, &policy->min_entropy_bits_per_byte);

    pos = find_json_key(json_str, "noise_source_count");
    if (pos) {
        int64_t v = 0;
        if (parse_int_val(pos, &v) == 0) policy->noise_source_count = (uint32_t)v;
    }

    pos = find_json_key(json_str, "cryptographic_conditioner");
    if (pos) parse_string_val(pos, policy->cryptographic_conditioner, sizeof(policy->cryptographic_conditioner));

    pos = find_json_key(json_str, "compression_ratio");
    if (pos) parse_double_val(pos, &policy->compression_ratio);

    pos = find_json_key(json_str, "rct_enabled");
    if (pos) parse_bool_val(pos, &policy->rct_enabled);

    pos = find_json_key(json_str, "apt_enabled");
    if (pos) parse_bool_val(pos, &policy->apt_enabled);

    pos = find_json_key(json_str, "halt_feed_on_health_fault");
    if (pos) parse_bool_val(pos, &policy->halt_feed_on_health_fault);

    pos = find_json_key(json_str, "startup_conditioning_samples");
    if (pos) {
        int64_t v = 0;
        if (parse_int_val(pos, &v) == 0) policy->startup_conditioning_samples = (uint32_t)v;
    }

    pos = find_json_key(json_str, "entropy_credit_derating_factor");
    if (pos) parse_double_val(pos, &policy->entropy_credit_derating_factor);

    pos = find_json_key(json_str, "credit_full_raw_bitcount");
    if (pos) parse_bool_val(pos, &policy->credit_full_raw_bitcount);

    pos = find_json_key(json_str, "mlockall_enabled");
    if (pos) parse_bool_val(pos, &policy->mlockall_enabled);

    pos = find_json_key(json_str, "zeroize_buffers_after_feed");
    if (pos) parse_bool_val(pos, &policy->zeroize_buffers_after_feed);

    pos = find_json_key(json_str, "adc_rail_saturation_guard");
    if (pos) parse_bool_val(pos, &policy->adc_rail_saturation_guard);

    pos = find_json_key(json_str, "max_serial_autocorrelation");
    if (pos) parse_double_val(pos, &policy->max_serial_autocorrelation);

    pos = find_json_key(json_str, "drop_privileges_cap_sys_admin_only");
    if (pos) parse_bool_val(pos, &policy->drop_privileges_cap_sys_admin_only);

    pos = find_json_key(json_str, "seccomp_syscall_filter");
    if (pos) parse_bool_val(pos, &policy->seccomp_syscall_filter);

    pos = find_json_key(json_str, "write_wakeup_threshold_bits");
    if (pos) {
        int64_t v = 0;
        if (parse_int_val(pos, &v) == 0) policy->write_wakeup_threshold_bits = (uint32_t)v;
    }

    pos = find_json_key(json_str, "max_reseed_interval_sec");
    if (pos) {
        int64_t v = 0;
        if (parse_int_val(pos, &v) == 0) policy->max_reseed_interval_sec = (uint32_t)v;
    }

    pos = find_json_key(json_str, "conditioner_startup_kat_verified");
    if (pos) parse_bool_val(pos, &policy->conditioner_startup_kat_verified);

    pos = find_json_key(json_str, "log_health_test_failures");
    if (pos) parse_bool_val(pos, &policy->log_health_test_failures);

    return 0;
}

int parse_entropy_policy_file(const char *filepath, entropy_policy_t *policy) {
    if (!filepath || !policy) return -1;
    FILE *f = fopen(filepath, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0 || sz > 1024 * 1024) {
        fclose(f);
        return -1;
    }

    char *buf = (char *)malloc(sz + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }

    size_t rd = fread(buf, 1, sz, f);
    buf[rd] = '\0';
    fclose(f);

    int rc = parse_entropy_policy_json(buf, policy);
    free(buf);
    return rc;
}

int parse_noise_buffer_json(const char *json_str, raw_noise_buffer_t *noise) {
    if (!json_str || !noise) return -1;
    memset(noise, 0, sizeof(raw_noise_buffer_t));

    const char *pos = find_json_key(json_str, "samples");
    if (!pos) return -1;

    while (*pos && *pos != '[') pos++;
    if (*pos != '[') return -1;
    pos++;

    uint32_t count = 0;
    while (*pos && *pos != ']' && count < LH_ENT_MAX_NOISE_SAMPLES) {
        skip_ws(&pos);
        if (*pos == ']') break;

        char *endp = NULL;
        long val = 0;
        if (pos[0] == '0' && (pos[1] == 'x' || pos[1] == 'X')) {
            val = strtol(pos, &endp, 16);
        } else {
            val = strtol(pos, &endp, 10);
        }

        if (endp == pos) {
            pos++;
            continue;
        }

        noise->samples[count++] = (uint8_t)(val & 0xff);
        pos = endp;
    }

    noise->count = count;
    return (count > 0) ? 0 : -1;
}

int parse_noise_buffer_file(const char *filepath, raw_noise_buffer_t *noise) {
    if (!filepath || !noise) return -1;
    FILE *f = fopen(filepath, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0 || sz > 10 * 1024 * 1024) {
        fclose(f);
        return -1;
    }

    char *buf = (char *)malloc(sz + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }

    size_t rd = fread(buf, 1, sz, f);
    buf[rd] = '\0';
    fclose(f);

    int rc = parse_noise_buffer_json(buf, noise);
    free(buf);
    return rc;
}
