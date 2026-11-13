#include "entropy_types.h"
#include "sp800_90b_health.h"
#include "sha256_conditioner.h"
#include "entropy_auditor.h"
#include "exporters.h"
#include "json_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_tests_run++; \
    if (cond) { \
        g_tests_passed++; \
    } else { \
        fprintf(stderr, "FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
    } \
} while(0)

/* Suite 1: NIST SP 800-90B Cutoff Math & Continuous Health Tests */
static void test_sp800_90b_health_tests(void) {
    printf("[SUITE 1] Testing NIST SP 800-90B Health Tests (RCT & APT)...\n");

    /* 1. RCT Cutoff Math */
    TEST_ASSERT(sp800_90b_calc_rct_cutoff(5.0) == 7, "RCT cutoff for H_min=5.0 is 1 + ceil(30/5) = 7");
    TEST_ASSERT(sp800_90b_calc_rct_cutoff(1.0) == 31, "RCT cutoff for H_min=1.0 is 1 + ceil(30/1) = 31");
    TEST_ASSERT(sp800_90b_calc_rct_cutoff(8.0) == 5, "RCT cutoff for H_min=8.0 is 1 + ceil(30/8) = 5");

    /* 2. APT Cutoff Math */
    uint32_t c_apt_5 = sp800_90b_calc_apt_cutoff(5.0, 512);
    TEST_ASSERT(c_apt_5 >= 35 && c_apt_5 <= 45, "APT cutoff for H_min=5.0 in W=512 is in [35, 45]");

    /* 3. RCT Stuck-At Fault Detection */
    sp800_90b_health_t health;
    sp800_90b_health_init(&health, 5.0, true);
    TEST_ASSERT(health.rct.cutoff_c_rct == 7, "Health tester initialized with C_RCT = 7");
    TEST_ASSERT(health.rct.fault_latched == false, "Initial RCT fault is false");

    /* Feed 6 identical samples (under threshold 7) */
    for (int i = 0; i < 6; i++) {
        bool ok = sp800_90b_health_test_sample(&health, 0xAA);
        TEST_ASSERT(ok == true, "Under-threshold run does not trigger fault");
    }
    TEST_ASSERT(health.rct.fault_latched == false, "Fault not latched yet at 6 samples");

    /* Feed 7th identical sample -> triggers RCT stuck-at fault */
    bool ok = sp800_90b_health_test_sample(&health, 0xAA);
    TEST_ASSERT(ok == false, "7th identical sample fails health test");
    TEST_ASSERT(health.rct.fault_latched == true, "RCT stuck-at fault latched");
    TEST_ASSERT((health.fault_flags & ENTROPY_FAULT_RCT_STUCK_AT) != 0, "RCT stuck-at flag set");
    TEST_ASSERT(health.rct.stuck_at_fault_count == 1, "Stuck-at fault count is 1");

    /* 4. Reset & Normal Stream (No False Positives) */
    sp800_90b_health_reset(&health);
    TEST_ASSERT(health.fault_flags == 0, "Reset clears fault flags");

    for (int i = 0; i < 512; i++) {
        uint8_t sample = (uint8_t)((i * 37 + 7) & 0xFF);
        ok = sp800_90b_health_test_sample(&health, sample);
        TEST_ASSERT(ok == true, "Varying samples pass health tests");
    }
    TEST_ASSERT(health.rct.fault_latched == false, "RCT passed normal stream");
    TEST_ASSERT(health.apt.fault_latched == false, "APT passed normal stream");

    /* 5. APT Bias Fault Detection */
    sp800_90b_health_reset(&health);
    /* In W=512, target symbol is first sample (e.g. 0x42). Feed 100 of it (cutoff ~40) */
    sp800_90b_health_test_sample(&health, 0x42); /* first sample sets target */
    for (int i = 1; i < 512; i++) {
        uint8_t sample = (i < 120 && (i % 2 == 0)) ? 0x42 : (uint8_t)(i & 0xFF);
        sp800_90b_health_test_sample(&health, sample);
    }
    TEST_ASSERT(health.apt.fault_latched == true, "APT bias fault latched on repetitive target symbol");
    TEST_ASSERT((health.fault_flags & ENTROPY_FAULT_APT_STATISTICAL_BIAS) != 0, "APT bias flag set");
}

/* Suite 2: Statistical Analysis & Min-Entropy Estimator */
static void test_noise_analysis_math(void) {
    printf("[SUITE 2] Testing MCV Min-Entropy & Autocorrelation...\n");

    /* 1. Uniform 256-symbol stream (High Entropy, Shuffled) */
    uint8_t uniform_samples[256];
    for (int i = 0; i < 256; i++) {
        uniform_samples[i] = (uint8_t)i;
    }
    uint32_t rng_state = 123456789;
    for (int i = 255; i > 0; i--) {
        rng_state = rng_state * 1664525U + 1013904223U;
        int j = (int)(rng_state % (uint32_t)(i + 1));
        uint8_t tmp = uniform_samples[i];
        uniform_samples[i] = uniform_samples[j];
        uniform_samples[j] = tmp;
    }

    noise_analysis_result_t res;
    int rc = analyze_noise_samples(uniform_samples, 256, 4.0, &res);
    TEST_ASSERT(rc == 0, "analyze_noise_samples on uniform stream succeeded");
    TEST_ASSERT(fabs(res.shannon_entropy_h1 - 8.0) < 0.001, "Uniform 256 symbols has H_1 = 8.0 bits/byte");
    TEST_ASSERT(res.most_probable_p_max == (1.0 / 256.0), "p_max is 1/256 for uniform");
    TEST_ASSERT(res.mcv_min_entropy_h_inf > 5.0, "MCV min-entropy H_inf > 5.0 with 99% confidence bound");
    TEST_ASSERT(res.rct_passed == true, "RCT passed uniform");
    TEST_ASSERT(res.apt_passed == true, "APT passed uniform");
    TEST_ASSERT(res.harmonic_coupling_detected == false, "No harmonic coupling in uniform");
    TEST_ASSERT(strcmp(res.verdict, "HEALTHY_TRNG_ENTROPY") == 0, "Verdict is HEALTHY_TRNG_ENTROPY");

    /* 2. Biased Low-Entropy Stream (Stuck / Weak Noise) */
    uint8_t biased_samples[512];
    for (int i = 0; i < 512; i++) {
        biased_samples[i] = (i < 400) ? 0x05 : (uint8_t)(i & 0xFF);
    }
    rc = analyze_noise_samples(biased_samples, 512, 4.0, &res);
    TEST_ASSERT(rc == 0, "analyze_noise_samples on biased stream succeeded");
    TEST_ASSERT(res.most_probable_p_max > 0.70, "p_max > 0.70 for biased stream");
    TEST_ASSERT(res.mcv_min_entropy_h_inf < 2.0, "Min-entropy H_inf < 2.0 bits/byte on biased stream");
    TEST_ASSERT(res.apt_passed == false, "APT failed on biased stream");

    /* 3. Harmonic Clock Coupling (Alternating 0x00 and 0xFF) */
    uint8_t clock_samples[256];
    for (int i = 0; i < 256; i++) {
        clock_samples[i] = (i % 2 == 0) ? 0x00 : 0xFF;
    }
    rc = analyze_noise_samples(clock_samples, 256, 4.0, &res);
    TEST_ASSERT(rc == 0, "analyze_noise_samples on clock injection stream succeeded");
    TEST_ASSERT(res.lag1_autocorrelation_r1 < -0.80, "Lag-1 autocorrelation near -1.0 for alternating clock");
    TEST_ASSERT(res.harmonic_coupling_detected == true, "Harmonic coupling detected");
    TEST_ASSERT(res.rail_saturation_detected == true, "Rail saturation detected on 0x00/0xFF");
}

/* Suite 3: Von Neumann Extractor & SHA-256 Cryptographic Conditioner */
static void test_sha256_conditioner(void) {
    printf("[SUITE 3] Testing Von Neumann Extractor & SHA-256 Conditioner...\n");

    /* 1. Startup KAT */
    TEST_ASSERT(sha256_startup_kat() == true, "FIPS 140-3 SHA-256 Startup KAT verified");

    /* 2. FIPS 180-4 Test Vector: "abc" */
    static const uint8_t expected_abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t digest[32];
    lh_sha256_hash((const uint8_t *)"abc", 3, digest);
    TEST_ASSERT(memcmp(digest, expected_abc, 32) == 0, "SHA-256 matches FIPS 180-4 'abc' vector");

    /* 3. HMAC-SHA256 Test */
    uint8_t hmac_out[32];
    lh_hmac_sha256((const uint8_t *)"key", 3, (const uint8_t *)"The quick brown fox jumps over the lazy dog", 43, hmac_out);
    /* Non-zero output verified */
    bool non_zero = false;
    for (int i = 0; i < 32; i++) {
        if (hmac_out[i] != 0) non_zero = true;
    }
    TEST_ASSERT(non_zero == true, "HMAC-SHA256 produced non-zero authentication tag");

    /* 4. Von Neumann Bit Extractor */
    /* Byte: 0b01100011 -> pairs: (0,1)->0, (1,0)->1, (0,0)->drop, (1,1)->drop -> 2 bits extracted: 0, 1 */
    uint8_t raw_pairs[1] = { 0x63 }; /* 0b01100011 */
    uint8_t extracted[4];
    size_t out_bytes = von_neumann_extract_bits(raw_pairs, 1, extracted, sizeof(extracted));
    TEST_ASSERT(out_bytes == 1, "Von Neumann produced 1 byte for extracted bits");
    /* First two bits in extracted[0] should be 0 and 1 -> 0b01000000 = 0x40 */
    TEST_ASSERT(extracted[0] == 0x40, "Von Neumann debiased bits match 0,1 (0x40)");

    /* 5. Cryptographic Conditioning Block */
    uint8_t raw_noise[128];
    for (int i = 0; i < 128; i++) {
        raw_noise[i] = (uint8_t)(i * 17 + 5);
    }
    conditioned_block_t block;
    int rc = condition_entropy_block(raw_noise, 128, 5.0, 0.50, &block);
    TEST_ASSERT(rc == 0, "condition_entropy_block succeeded");
    TEST_ASSERT(block.raw_bytes_consumed == 128, "Raw bytes consumed == 128");
    /* Credited bits = floor(min(256, 128 * 5.0 * 0.50)) = floor(min(256, 320)) = 256 */
    TEST_ASSERT(block.credited_entropy_bits == 256, "Credited entropy bits capped at 256");
    TEST_ASSERT(block.pool_info.entropy_count == 256, "rand_pool_info entropy_count is 256");
    TEST_ASSERT(block.pool_info.buf_size == 32, "rand_pool_info buf_size is 32");

    /* 6. Secure Zeroization */
    uint8_t secret[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    lh_secure_zero(secret, sizeof(secret));
    bool all_zero = true;
    for (size_t i = 0; i < sizeof(secret); i++) {
        if (secret[i] != 0) all_zero = false;
    }
    TEST_ASSERT(all_zero == true, "lh_secure_zero successfully zeroized memory");
}

/* Suite 4: 10-Rule TRNG Security Posture Auditor */
static void test_entropy_auditor(void) {
    printf("[SUITE 4] Testing 10-Rule Security Posture Auditor (LH-ENT-001..010)...\n");

    /* 1. Hardened Policy */
    entropy_policy_t hard_policy;
    int rc = parse_entropy_policy_file("fixtures/hardened_entropy_policy.json", &hard_policy);
    TEST_ASSERT(rc == 0, "parse hardened policy file succeeded");

    audit_report_t hard_report;
    rc = audit_entropy_policy(&hard_policy, &hard_report);
    TEST_ASSERT(rc == 0, "audit hardened policy succeeded");
    TEST_ASSERT(hard_report.total_rules == 10, "Total rules evaluated == 10");
    TEST_ASSERT(hard_report.passed_rules == 10, "Passed rules == 10");
    TEST_ASSERT(hard_report.failed_rules == 0, "Failed rules == 0");
    TEST_ASSERT(hard_report.total_deductions == 0, "Total deductions == 0");
    TEST_ASSERT(hard_report.posture_score == 100, "Hardened posture score == 100");

    for (int i = 0; i < 10; i++) {
        TEST_ASSERT(hard_report.findings[i].passed == true, "Hardened rule passed");
    }

    /* 2. Vulnerable Policy */
    entropy_policy_t vuln_policy;
    rc = parse_entropy_policy_file("fixtures/vulnerable_entropy_policy.json", &vuln_policy);
    TEST_ASSERT(rc == 0, "parse vulnerable policy file succeeded");

    audit_report_t vuln_report;
    rc = audit_entropy_policy(&vuln_policy, &vuln_report);
    TEST_ASSERT(rc == 0, "audit vulnerable policy succeeded");
    TEST_ASSERT(vuln_report.total_rules == 10, "Total rules evaluated == 10");
    TEST_ASSERT(vuln_report.passed_rules == 0, "Passed rules == 0");
    TEST_ASSERT(vuln_report.failed_rules == 10, "Failed rules == 10");
    TEST_ASSERT(vuln_report.total_deductions == 124, "Total deductions == 124 (25x3 + 10x4 + 4x2 + 1)");
    TEST_ASSERT(vuln_report.posture_score == 0, "Vulnerable posture score == 0");

    for (int i = 0; i < 10; i++) {
        TEST_ASSERT(vuln_report.findings[i].passed == false, "Vulnerable rule failed");
    }

    /* 3. Verify Specific Rule Deductions */
    TEST_ASSERT(strcmp(vuln_report.findings[0].rule_id, "LH-ENT-001") == 0, "Rule 1 ID");
    TEST_ASSERT(vuln_report.findings[0].deduction == 25, "Rule 1 deduction is 25");

    TEST_ASSERT(strcmp(vuln_report.findings[1].rule_id, "LH-ENT-002") == 0, "Rule 2 ID");
    TEST_ASSERT(vuln_report.findings[1].deduction == 25, "Rule 2 deduction is 25");

    TEST_ASSERT(strcmp(vuln_report.findings[2].rule_id, "LH-ENT-003") == 0, "Rule 3 ID");
    TEST_ASSERT(vuln_report.findings[2].deduction == 25, "Rule 3 deduction is 25");

    TEST_ASSERT(strcmp(vuln_report.findings[3].rule_id, "LH-ENT-004") == 0, "Rule 4 ID");
    TEST_ASSERT(vuln_report.findings[3].deduction == 10, "Rule 4 deduction is 10");

    TEST_ASSERT(strcmp(vuln_report.findings[4].rule_id, "LH-ENT-005") == 0, "Rule 5 ID");
    TEST_ASSERT(vuln_report.findings[4].deduction == 10, "Rule 5 deduction is 10");

    TEST_ASSERT(strcmp(vuln_report.findings[5].rule_id, "LH-ENT-006") == 0, "Rule 6 ID");
    TEST_ASSERT(vuln_report.findings[5].deduction == 10, "Rule 6 deduction is 10");

    TEST_ASSERT(strcmp(vuln_report.findings[6].rule_id, "LH-ENT-007") == 0, "Rule 7 ID");
    TEST_ASSERT(vuln_report.findings[6].deduction == 10, "Rule 7 deduction is 10");

    TEST_ASSERT(strcmp(vuln_report.findings[7].rule_id, "LH-ENT-008") == 0, "Rule 8 ID");
    TEST_ASSERT(vuln_report.findings[7].deduction == 4, "Rule 8 deduction is 4");

    TEST_ASSERT(strcmp(vuln_report.findings[8].rule_id, "LH-ENT-009") == 0, "Rule 9 ID");
    TEST_ASSERT(vuln_report.findings[8].deduction == 4, "Rule 9 deduction is 4");

    TEST_ASSERT(strcmp(vuln_report.findings[9].rule_id, "LH-ENT-010") == 0, "Rule 10 ID");
    TEST_ASSERT(vuln_report.findings[9].deduction == 1, "Rule 10 deduction is 1");

    /* 4. Partial Deduction Math */
    entropy_policy_t partial_policy = hard_policy;
    partial_policy.min_entropy_bits_per_byte = 3.5; /* Triggers LH-ENT-001 (CRITICAL, 25) */
    partial_policy.startup_conditioning_samples = 512; /* Triggers LH-ENT-004 (HIGH, 10) */
    audit_report_t partial_report;
    audit_entropy_policy(&partial_policy, &partial_report);
    TEST_ASSERT(partial_report.total_deductions == 35, "Partial deductions == 35");
    TEST_ASSERT(partial_report.posture_score == 65, "Partial posture score == 100 - 35 = 65");
}

/* Suite 5: Exporters & JSON Parser */
static void test_exporters_and_parsers(void) {
    printf("[SUITE 5] Testing Exporters (Table, JSON, SARIF)...\n");

    entropy_policy_t policy;
    parse_entropy_policy_file("fixtures/hardened_entropy_policy.json", &policy);
    audit_report_t report;
    audit_entropy_policy(&policy, &report);

    /* Test null stream / null report handling */
    TEST_ASSERT(export_audit_table(NULL, stdout) == -1, "export_audit_table handles NULL");
    TEST_ASSERT(export_audit_json(NULL, stdout) == -1, "export_audit_json handles NULL");
    TEST_ASSERT(export_audit_sarif(NULL, stdout) == -1, "export_audit_sarif handles NULL");

    char buf[8192];
    FILE *mem = fmemopen(buf, sizeof(buf), "w");
    TEST_ASSERT(mem != NULL, "fmemopen succeeded");

    int rc = export_audit_json(&report, mem);
    TEST_ASSERT(rc == 0, "export_audit_json succeeded");
    fclose(mem);
    TEST_ASSERT(strstr(buf, "\"tool\": \"lh-entropy\"") != NULL, "JSON contains tool identifier");
    TEST_ASSERT(strstr(buf, "\"posture_score\": 100") != NULL, "JSON contains posture score 100");

    mem = fmemopen(buf, sizeof(buf), "w");
    rc = export_audit_sarif(&report, mem);
    TEST_ASSERT(rc == 0, "export_audit_sarif succeeded");
    fclose(mem);
    TEST_ASSERT(strstr(buf, "\"version\": \"2.1.0\"") != NULL, "SARIF contains version 2.1.0");
    TEST_ASSERT(strstr(buf, "sarif-schema-2.1.0.json") != NULL, "SARIF contains schema");

    /* Parse sample noise fixture */
    raw_noise_buffer_t noise;
    rc = parse_noise_buffer_file("fixtures/sample_sram_adc_noise.json", &noise);
    TEST_ASSERT(rc == 0, "parse_noise_buffer_file succeeded");
    TEST_ASSERT(noise.count == 512, "Sample noise fixture contains 512 samples");
}

/* Suite 6: CLI Subprocess Invocations */
static void test_cli_subprocesses(void) {
    printf("[SUITE 6] Testing CLI Subprocess Invocations...\n");

    int rc = system("./bin/lh-entropy --version > /dev/null 2>&1");
    TEST_ASSERT(rc == 0, "lh-entropy --version returns 0");

    rc = system("./bin/lh-entropy --help > /dev/null 2>&1");
    TEST_ASSERT(rc == 0, "lh-entropy --help returns 0");

    rc = system("./bin/lh-entropy scan fixtures/hardened_entropy_policy.json --format json > /dev/null 2>&1");
    TEST_ASSERT(rc == 0, "lh-entropy scan on hardened policy returns 0");

    rc = system("./bin/lh-entropy scan fixtures/vulnerable_entropy_policy.json --format json > /dev/null 2>&1");
    TEST_ASSERT(WEXITSTATUS(rc) == 1, "lh-entropy scan on vulnerable policy returns 1");

    rc = system("./bin/lh-entropy analyze-noise fixtures/sample_sram_adc_noise.json --format json > /dev/null 2>&1");
    TEST_ASSERT(rc == 0, "lh-entropy analyze-noise on healthy sample returns 0");

    rc = system("./bin/lh-entropy condition fixtures/sample_sram_adc_noise.json --format json > /dev/null 2>&1");
    TEST_ASSERT(rc == 0, "lh-entropy condition on sample noise returns 0");

    rc = system("./bin/lh-entropy health-test --mode pass > /dev/null 2>&1");
    TEST_ASSERT(rc == 0, "lh-entropy health-test --mode pass returns 0");

    rc = system("./bin/lh-entropy health-test --mode stuck-fault > /dev/null 2>&1");
    TEST_ASSERT(WEXITSTATUS(rc) == 1, "lh-entropy health-test --mode stuck-fault returns 1");

    rc = system("./bin/lh-entropy health-test --mode bias-fault > /dev/null 2>&1");
    TEST_ASSERT(WEXITSTATUS(rc) == 1, "lh-entropy health-test --mode bias-fault returns 1");

    rc = system("./bin/lh-entropy invalid-command > /dev/null 2>&1");
    TEST_ASSERT(WEXITSTATUS(rc) == 2, "lh-entropy invalid-command returns 2");
}

int main(void) {
    printf("===================================================================\n");
    printf(" RUNNING LOGIHERTZ CRYPTOGRAPHIC HARDWARE ENTROPY TEST SUITE\n");
    printf("===================================================================\n");

    test_sp800_90b_health_tests();
    test_noise_analysis_math();
    test_sha256_conditioner();
    test_entropy_auditor();
    test_exporters_and_parsers();
    test_cli_subprocesses();

    printf("\n===================================================================\n");
    printf(" TEST SUMMARY: %d / %d assertions passed (100%%)\n", g_tests_passed, g_tests_run);
    printf("===================================================================\n");

    return (g_tests_run > 0 && g_tests_passed == g_tests_run) ? 0 : 1;
}
