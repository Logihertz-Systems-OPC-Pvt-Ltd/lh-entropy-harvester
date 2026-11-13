#include "sp800_90b_health.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define Z_ALPHA_30 5.997807       /* Normal quantile for alpha = 2^-30 */
#define Z_CONF_995 2.5758293      /* 99% confidence upper bound (Z_0.995) */

uint32_t sp800_90b_calc_rct_cutoff(double h_min) {
    if (h_min <= 0.01) h_min = 0.01;
    uint32_t c = 1 + (uint32_t)ceil(30.0 / h_min);
    return c;
}

uint32_t sp800_90b_calc_apt_cutoff(double h_min, uint32_t window_size) {
    if (h_min <= 0.01) h_min = 0.01;
    if (window_size == 0) window_size = LH_ENT_APT_WINDOW_SIZE;

    double p = pow(2.0, -h_min);
    if (p >= 1.0) p = 0.9999;
    if (p <= 0.0) p = 1e-9;

    double mu = (double)window_size * p;
    double sigma = sqrt((double)window_size * p * (1.0 - p));
    double cutoff_val = mu + Z_ALPHA_30 * sigma;

    uint32_t c = (uint32_t)ceil(cutoff_val);
    if (c > window_size) c = window_size;
    if (c < 2) c = 2;
    return c;
}

void sp800_90b_health_init(sp800_90b_health_t *health, double h_min, bool halt_on_fault) {
    if (!health) return;
    memset(health, 0, sizeof(sp800_90b_health_t));

    if (h_min <= 0.01) h_min = 1.0;
    health->halt_on_fault = halt_on_fault;
    health->fault_flags = ENTROPY_FAULT_NONE;

    /* Initialize RCT state */
    health->rct.assessed_h_min = h_min;
    health->rct.cutoff_c_rct = sp800_90b_calc_rct_cutoff(h_min);
    health->rct.current_run = 0;
    health->rct.fault_latched = false;

    /* Initialize APT state */
    health->apt.assessed_h_min = h_min;
    health->apt.window_size = LH_ENT_APT_WINDOW_SIZE;
    health->apt.cutoff_c_apt = sp800_90b_calc_apt_cutoff(h_min, LH_ENT_APT_WINDOW_SIZE);
    health->apt.current_window_index = 0;
    health->apt.target_count = 0;
    health->apt.fault_latched = false;
}

void sp800_90b_health_reset(sp800_90b_health_t *health) {
    if (!health) return;
    double h_min = health->rct.assessed_h_min;
    bool halt = health->halt_on_fault;
    sp800_90b_health_init(health, h_min, halt);
}

bool sp800_90b_health_test_sample(sp800_90b_health_t *health, uint8_t sample) {
    if (!health) return false;

    if (health->fault_flags != ENTROPY_FAULT_NONE && health->halt_on_fault) {
        return false;
    }

    /* 1. Repetition Count Test (RCT) */
    health->rct.total_samples_tested++;
    if (health->rct.total_samples_tested == 1) {
        health->rct.last_sample = sample;
        health->rct.current_run = 1;
    } else {
        if (sample == health->rct.last_sample) {
            health->rct.current_run++;
            if (health->rct.current_run >= health->rct.cutoff_c_rct) {
                health->rct.fault_latched = true;
                health->rct.stuck_at_fault_count++;
                health->fault_flags |= ENTROPY_FAULT_RCT_STUCK_AT;
            }
        } else {
            health->rct.last_sample = sample;
            health->rct.current_run = 1;
        }
    }

    /* 2. Adaptive Proportion Test (APT) */
    if (health->apt.current_window_index == 0) {
        health->apt.target_symbol = sample;
        health->apt.target_count = 1;
        health->apt.current_window_index = 1;
    } else {
        if (sample == health->apt.target_symbol) {
            health->apt.target_count++;
            if (health->apt.target_count >= health->apt.cutoff_c_apt) {
                health->apt.fault_latched = true;
                health->apt.bias_fault_count++;
                health->fault_flags |= ENTROPY_FAULT_APT_STATISTICAL_BIAS;
            }
        }
        health->apt.current_window_index++;
        if (health->apt.current_window_index >= health->apt.window_size) {
            /* Window completed */
            health->apt.total_windows_tested++;
            health->apt.current_window_index = 0;
            health->apt.target_count = 0;
        }
    }

    if (health->fault_flags != ENTROPY_FAULT_NONE && health->halt_on_fault) {
        return false;
    }

    return true;
}

int analyze_noise_samples(const uint8_t *samples, uint32_t count, double target_h_min, noise_analysis_result_t *result) {
    if (!samples || count == 0 || !result) return -1;
    memset(result, 0, sizeof(noise_analysis_result_t));

    result->sample_count = count;
    double eff_h_min = (target_h_min > 0.1) ? target_h_min : 4.0;
    result->rct_cutoff = sp800_90b_calc_rct_cutoff(eff_h_min);
    result->apt_cutoff = sp800_90b_calc_apt_cutoff(eff_h_min, LH_ENT_APT_WINDOW_SIZE);

    /* 1. Calculate Histogram & Symbol Frequencies */
    uint32_t freq[256];
    memset(freq, 0, sizeof(freq));
    for (uint32_t i = 0; i < count; i++) {
        freq[samples[i]]++;
    }

    /* 2. Shannon Entropy H_1 & Max Probability p_max */
    double h1 = 0.0;
    uint32_t max_count = 0;
    for (int b = 0; b < 256; b++) {
        if (freq[b] > max_count) {
            max_count = freq[b];
        }
        if (freq[b] > 0) {
            double p = (double)freq[b] / (double)count;
            h1 -= p * (log(p) / log(2.0));
        }
    }
    result->shannon_entropy_h1 = h1;

    double p_max = (double)max_count / (double)count;
    result->most_probable_p_max = p_max;

    /* 3. 99% Confidence Upper Bound p_u on Most Probable Symbol (NIST SP 800-90B Sec 6.3.1) */
    double denom = (count > 1) ? (count - 1) : 1;
    double p_u = p_max + Z_CONF_995 * sqrt((p_max * (1.0 - p_max)) / denom);
    if (p_u > 1.0) p_u = 1.0;
    result->upper_bound_p_u = p_u;

    if (p_u > 0.0) {
        result->mcv_min_entropy_h_inf = - (log(p_u) / log(2.0));
    } else {
        result->mcv_min_entropy_h_inf = 8.0;
    }
    result->mcv_min_entropy_per_bit = result->mcv_min_entropy_h_inf / 8.0;

    /* 4. Lag-1 Serial Pearson Autocorrelation r_1 */
    double mean = 0.0;
    for (uint32_t i = 0; i < count; i++) {
        mean += (double)samples[i];
    }
    mean /= (double)count;

    double num = 0.0;
    double den = 0.0;
    for (uint32_t i = 0; i < count; i++) {
        double diff = (double)samples[i] - mean;
        den += diff * diff;
        if (i + 1 < count) {
            double diff_next = (double)samples[i + 1] - mean;
            num += diff * diff_next;
        }
    }
    if (den > 1e-9) {
        result->lag1_autocorrelation_r1 = num / den;
    } else {
        result->lag1_autocorrelation_r1 = 0.0;
    }

    if (fabs(result->lag1_autocorrelation_r1) > 0.15) {
        result->harmonic_coupling_detected = true;
    }

    /* 5. Rail Saturation (Excessive 0x00 or 0xFF) */
    double rail_ratio = (double)(freq[0] + freq[255]) / (double)count;
    if (rail_ratio > 0.10 || ((double)freq[0] / count) > 0.06 || ((double)freq[255] / count) > 0.06) {
        result->rail_saturation_detected = true;
    }

    /* 6. Run Continuous Health Tests on Stream */
    sp800_90b_health_t health;
    sp800_90b_health_init(&health, eff_h_min, false);

    for (uint32_t i = 0; i < count; i++) {
        sp800_90b_health_test_sample(&health, samples[i]);
    }

    result->rct_passed = !health.rct.fault_latched;
    result->apt_passed = !health.apt.fault_latched;

    /* Verdict */
    if (result->rct_passed && result->apt_passed && !result->harmonic_coupling_detected &&
        !result->rail_saturation_detected && result->mcv_min_entropy_h_inf >= eff_h_min) {
        snprintf(result->verdict, sizeof(result->verdict), "HEALTHY_TRNG_ENTROPY");
    } else if (!result->rct_passed) {
        snprintf(result->verdict, sizeof(result->verdict), "FAULT_RCT_STUCK_AT");
    } else if (!result->apt_passed) {
        snprintf(result->verdict, sizeof(result->verdict), "FAULT_APT_STATISTICAL_BIAS");
    } else if (result->harmonic_coupling_detected) {
        snprintf(result->verdict, sizeof(result->verdict), "FAULT_HARMONIC_INJECTION");
    } else if (result->rail_saturation_detected) {
        snprintf(result->verdict, sizeof(result->verdict), "FAULT_ADC_RAIL_SATURATION");
    } else {
        snprintf(result->verdict, sizeof(result->verdict), "WARNING_LOW_MIN_ENTROPY");
    }

    return 0;
}
