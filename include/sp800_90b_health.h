#ifndef LH_SP800_90B_HEALTH_H
#define LH_SP800_90B_HEALTH_H

#include "entropy_types.h"

/* NIST SP 800-90B Cutoff Calculations */
uint32_t sp800_90b_calc_rct_cutoff(double h_min);
uint32_t sp800_90b_calc_apt_cutoff(double h_min, uint32_t window_size);

/* Health Tester Initialization & Reset */
void sp800_90b_health_init(sp800_90b_health_t *health, double h_min, bool halt_on_fault);
void sp800_90b_health_reset(sp800_90b_health_t *health);

/* Continuous Per-Sample Health Test Step */
bool sp800_90b_health_test_sample(sp800_90b_health_t *health, uint8_t sample);

/* Statistical Analysis & Min-Entropy Estimation */
int analyze_noise_samples(const uint8_t *samples, uint32_t count, double target_h_min, noise_analysis_result_t *result);

#endif /* LH_SP800_90B_HEALTH_H */
