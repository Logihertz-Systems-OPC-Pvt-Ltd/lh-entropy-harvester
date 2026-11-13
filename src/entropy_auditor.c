#include "entropy_auditor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool is_vetted_conditioner(const char *name) {
    if (!name) return false;
    return (strcmp(name, "SHA-256") == 0 ||
            strcmp(name, "HMAC-SHA256") == 0 ||
            strcmp(name, "AES-CBC-MAC") == 0);
}

int audit_entropy_policy(const entropy_policy_t *policy, audit_report_t *report) {
    if (!policy || !report) return -1;
    memset(report, 0, sizeof(audit_report_t));

    snprintf(report->policy_name, sizeof(report->policy_name), "%s", policy->policy_name);
    report->total_rules = LH_ENT_MAX_RULES;

    uint32_t total_deductions = 0;
    uint32_t passed_count = 0;
    uint32_t failed_count = 0;

    /* Rule 1: LH-ENT-001 (CRITICAL, 25, CWE-331) */
    {
        audit_finding_t *f = &report->findings[0];
        snprintf(f->rule_id, sizeof(f->rule_id), "LH-ENT-001");
        snprintf(f->rule_name, sizeof(f->rule_name), "Raw Noise Source Min-Entropy Floor & Redundancy");
        snprintf(f->cwe_id, sizeof(f->cwe_id), "CWE-331");
        f->severity = SEV_CRITICAL;
        f->deduction = 25;
        if (policy->min_entropy_bits_per_byte >= 4.0 && policy->noise_source_count >= 2) {
            f->passed = true;
            snprintf(f->details, sizeof(f->details), "Assessed min-entropy %.2f bits/byte >= 4.0 with %u redundant noise sources.",
                     policy->min_entropy_bits_per_byte, policy->noise_source_count);
            snprintf(f->recommendation, sizeof(f->recommendation), "Compliant with NIST SP 800-90B noise source requirements.");
            passed_count++;
        } else {
            f->passed = false;
            total_deductions += f->deduction;
            failed_count++;
            snprintf(f->details, sizeof(f->details), "Low min-entropy (%.2f < 4.0 bits/byte) or insufficient noise source redundancy (%u < 2).",
                     policy->min_entropy_bits_per_byte, policy->noise_source_count);
            snprintf(f->recommendation, sizeof(f->recommendation), "Enforce min-entropy >= 4.0 bits/byte and configure at least 2 independent noise sources.");
        }
    }

    /* Rule 2: LH-ENT-002 (CRITICAL, 25, CWE-338) */
    {
        audit_finding_t *f = &report->findings[1];
        snprintf(f->rule_id, sizeof(f->rule_id), "LH-ENT-002");
        snprintf(f->rule_name, sizeof(f->rule_name), "NIST SP 800-90B Vetted Cryptographic Conditioner");
        snprintf(f->cwe_id, sizeof(f->cwe_id), "CWE-338");
        f->severity = SEV_CRITICAL;
        f->deduction = 25;
        if (is_vetted_conditioner(policy->cryptographic_conditioner) && policy->compression_ratio >= 2.0) {
            f->passed = true;
            snprintf(f->details, sizeof(f->details), "Vetted conditioner '%s' active with compression ratio %.2fx >= 2.0x.",
                     policy->cryptographic_conditioner, policy->compression_ratio);
            snprintf(f->recommendation, sizeof(f->recommendation), "Compliant with vetted conditioning guidelines.");
            passed_count++;
        } else {
            f->passed = false;
            total_deductions += f->deduction;
            failed_count++;
            snprintf(f->details, sizeof(f->details), "Unvetted conditioner '%s' or insufficient compression ratio (%.2fx < 2.0x).",
                     policy->cryptographic_conditioner, policy->compression_ratio);
            snprintf(f->recommendation, sizeof(f->recommendation), "Use SHA-256, HMAC-SHA256, or AES-CBC-MAC with >= 2.0x input compression.");
        }
    }

    /* Rule 3: LH-ENT-003 (CRITICAL, 25, CWE-693) */
    {
        audit_finding_t *f = &report->findings[2];
        snprintf(f->rule_id, sizeof(f->rule_id), "LH-ENT-003");
        snprintf(f->rule_name, sizeof(f->rule_name), "Continuous Repetition Count & Adaptive Proportion Tests");
        snprintf(f->cwe_id, sizeof(f->cwe_id), "CWE-693");
        f->severity = SEV_CRITICAL;
        f->deduction = 25;
        if (policy->rct_enabled && policy->apt_enabled && policy->halt_feed_on_health_fault) {
            f->passed = true;
            snprintf(f->details, sizeof(f->details), "RCT and APT continuous health tests active with immediate feed shutdown on fault.");
            snprintf(f->recommendation, sizeof(f->recommendation), "Compliant with NIST SP 800-90B Section 4.4 health testing.");
            passed_count++;
        } else {
            f->passed = false;
            total_deductions += f->deduction;
            failed_count++;
            snprintf(f->details, sizeof(f->details), "Continuous health tests disabled (RCT: %s, APT: %s) or fail to halt feed on fault (%s).",
                     policy->rct_enabled ? "on" : "off", policy->apt_enabled ? "on" : "off",
                     policy->halt_feed_on_health_fault ? "true" : "false");
            snprintf(f->recommendation, sizeof(f->recommendation), "Enable both RCT and APT tests and enforce immediate feed termination upon fault latch.");
        }
    }

    /* Rule 4: LH-ENT-004 (HIGH, 10, CWE-330) */
    {
        audit_finding_t *f = &report->findings[3];
        snprintf(f->rule_id, sizeof(f->rule_id), "LH-ENT-004");
        snprintf(f->rule_name, sizeof(f->rule_name), "Startup Power-On Self-Test (POST) Conditioning");
        snprintf(f->cwe_id, sizeof(f->cwe_id), "CWE-330");
        f->severity = SEV_HIGH;
        f->deduction = 10;
        if (policy->startup_conditioning_samples >= 1024) {
            f->passed = true;
            snprintf(f->details, sizeof(f->details), "Startup POST collects %u samples >= 1024 before seeding kernel entropy pool.",
                     policy->startup_conditioning_samples);
            snprintf(f->recommendation, sizeof(f->recommendation), "Compliant with startup qualification standards.");
            passed_count++;
        } else {
            f->passed = false;
            total_deductions += f->deduction;
            failed_count++;
            snprintf(f->details, sizeof(f->details), "Insufficient startup conditioning samples (%u < 1024).",
                     policy->startup_conditioning_samples);
            snprintf(f->recommendation, sizeof(f->recommendation), "Accumulate and qualify at least 1024 startup samples before initial RNDADDENTROPY injection.");
        }
    }

    /* Rule 5: LH-ENT-005 (HIGH, 10, CWE-331) */
    {
        audit_finding_t *f = &report->findings[4];
        snprintf(f->rule_id, sizeof(f->rule_id), "LH-ENT-005");
        snprintf(f->rule_name, sizeof(f->rule_name), "Conservative Entropy Bit Crediting & Derating");
        snprintf(f->cwe_id, sizeof(f->cwe_id), "CWE-331");
        f->severity = SEV_HIGH;
        f->deduction = 10;
        if (policy->entropy_credit_derating_factor <= 0.75 && !policy->credit_full_raw_bitcount) {
            f->passed = true;
            snprintf(f->details, sizeof(f->details), "Conservative credit derating %.2f <= 0.75 with no full raw bit credit.",
                     policy->entropy_credit_derating_factor);
            snprintf(f->recommendation, sizeof(f->recommendation), "Compliant with conservative entropy estimation principles.");
            passed_count++;
        } else {
            f->passed = false;
            total_deductions += f->deduction;
            failed_count++;
            snprintf(f->details, sizeof(f->details), "Aggressive credit derating (%.2f > 0.75) or full raw bitcount credited (%s).",
                     policy->entropy_credit_derating_factor, policy->credit_full_raw_bitcount ? "true" : "false");
            snprintf(f->recommendation, sizeof(f->recommendation), "Cap entropy credit derating factor at 0.75 and never credit 1:1 raw bit counts.");
        }
    }

    /* Rule 6: LH-ENT-006 (HIGH, 10, CWE-226) */
    {
        audit_finding_t *f = &report->findings[5];
        snprintf(f->rule_id, sizeof(f->rule_id), "LH-ENT-006");
        snprintf(f->rule_name, sizeof(f->rule_name), "RAM Locking (mlockall) & Secure Buffer Zeroization");
        snprintf(f->cwe_id, sizeof(f->cwe_id), "CWE-226");
        f->severity = SEV_HIGH;
        f->deduction = 10;
        if (policy->mlockall_enabled && policy->zeroize_buffers_after_feed) {
            f->passed = true;
            snprintf(f->details, sizeof(f->details), "RAM pages locked via mlockall and intermediate noise buffers securely zeroized.");
            snprintf(f->recommendation, sizeof(f->recommendation), "Compliant with anti-paging and memory remanence protections.");
            passed_count++;
        } else {
            f->passed = false;
            total_deductions += f->deduction;
            failed_count++;
            snprintf(f->details, sizeof(f->details), "Memory locking disabled (mlockall: %s) or buffers not zeroized after feed (%s).",
                     policy->mlockall_enabled ? "true" : "false", policy->zeroize_buffers_after_feed ? "true" : "false");
            snprintf(f->recommendation, sizeof(f->recommendation), "Enable mlockall() to prevent swap leaks and zeroize volatile buffers immediately after hashing.");
        }
    }

    /* Rule 7: LH-ENT-007 (HIGH, 10, CWE-1300) */
    {
        audit_finding_t *f = &report->findings[6];
        snprintf(f->rule_id, sizeof(f->rule_id), "LH-ENT-007");
        snprintf(f->rule_name, sizeof(f->rule_name), "ADC Rail Saturation Guard & Harmonic Injection Filter");
        snprintf(f->cwe_id, sizeof(f->cwe_id), "CWE-1300");
        f->severity = SEV_HIGH;
        f->deduction = 10;
        if (policy->adc_rail_saturation_guard && policy->max_serial_autocorrelation <= 0.15) {
            f->passed = true;
            snprintf(f->details, sizeof(f->details), "ADC rail saturation guard active and serial autocorrelation bound %.2f <= 0.15.",
                     policy->max_serial_autocorrelation);
            snprintf(f->recommendation, sizeof(f->recommendation), "Compliant with analog frontend noise integrity standards.");
            passed_count++;
        } else {
            f->passed = false;
            total_deductions += f->deduction;
            failed_count++;
            snprintf(f->details, sizeof(f->details), "Rail saturation guard disabled (%s) or excessive autocorrelation tolerance (%.2f > 0.15).",
                     policy->adc_rail_saturation_guard ? "true" : "false", policy->max_serial_autocorrelation);
            snprintf(f->recommendation, sizeof(f->recommendation), "Enable ADC clipping detection and enforce lag-1 autocorrelation threshold <= 0.15.");
        }
    }

    /* Rule 8: LH-ENT-008 (MEDIUM, 4, CWE-250) */
    {
        audit_finding_t *f = &report->findings[7];
        snprintf(f->rule_id, sizeof(f->rule_id), "LH-ENT-008");
        snprintf(f->rule_name, sizeof(f->rule_name), "Privilege Demotion to CAP_SYS_ADMIN & Seccomp Sandbox");
        snprintf(f->cwe_id, sizeof(f->cwe_id), "CWE-250");
        f->severity = SEV_MEDIUM;
        f->deduction = 4;
        if (policy->drop_privileges_cap_sys_admin_only && policy->seccomp_syscall_filter) {
            f->passed = true;
            snprintf(f->details, sizeof(f->details), "Daemon demotes root privileges to CAP_SYS_ADMIN with strict seccomp BPF filter.");
            snprintf(f->recommendation, sizeof(f->recommendation), "Compliant with least privilege and process sandboxing.");
            passed_count++;
        } else {
            f->passed = false;
            total_deductions += f->deduction;
            failed_count++;
            snprintf(f->details, sizeof(f->details), "Daemon runs with unconstrained privileges (%s) or missing seccomp filter (%s).",
                     policy->drop_privileges_cap_sys_admin_only ? "restricted" : "unconstrained",
                     policy->seccomp_syscall_filter ? "active" : "disabled");
            snprintf(f->recommendation, sizeof(f->recommendation), "Drop root privileges to retain CAP_SYS_ADMIN only and attach a seccomp filter.");
        }
    }

    /* Rule 9: LH-ENT-009 (MEDIUM, 4, CWE-400) */
    {
        audit_finding_t *f = &report->findings[8];
        snprintf(f->rule_id, sizeof(f->rule_id), "LH-ENT-009");
        snprintf(f->rule_name, sizeof(f->rule_name), "Kernel Entropy Watermark & Reseed Interval Guard");
        snprintf(f->cwe_id, sizeof(f->cwe_id), "CWE-400");
        f->severity = SEV_MEDIUM;
        f->deduction = 4;
        if (policy->write_wakeup_threshold_bits >= 128 && policy->max_reseed_interval_sec <= 60) {
            f->passed = true;
            snprintf(f->details, sizeof(f->details), "Kernel wakeup threshold %u bits >= 128 and max reseed interval %u sec <= 60.",
                     policy->write_wakeup_threshold_bits, policy->max_reseed_interval_sec);
            snprintf(f->recommendation, sizeof(f->recommendation), "Compliant with kernel pool replenishment requirements.");
            passed_count++;
        } else {
            f->passed = false;
            total_deductions += f->deduction;
            failed_count++;
            snprintf(f->details, sizeof(f->details), "Low wakeup threshold (%u < 128 bits) or sluggish reseed interval (%u > 60 sec).",
                     policy->write_wakeup_threshold_bits, policy->max_reseed_interval_sec);
            snprintf(f->recommendation, sizeof(f->recommendation), "Set write_wakeup_threshold >= 128 bits and reseed within 60 seconds.");
        }
    }

    /* Rule 10: LH-ENT-010 (LOW, 1, CWE-778) */
    {
        audit_finding_t *f = &report->findings[9];
        snprintf(f->rule_id, sizeof(f->rule_id), "LH-ENT-010");
        snprintf(f->rule_name, sizeof(f->rule_name), "Conditioner Startup KAT & Health Fault Audit Logging");
        snprintf(f->cwe_id, sizeof(f->cwe_id), "CWE-778");
        f->severity = SEV_LOW;
        f->deduction = 1;
        if (policy->conditioner_startup_kat_verified && policy->log_health_test_failures) {
            f->passed = true;
            snprintf(f->details, sizeof(f->details), "FIPS 140-3 conditioner KAT verified on startup and health failures logged to syslog.");
            snprintf(f->recommendation, sizeof(f->recommendation), "Compliant with cryptographic auditability guidelines.");
            passed_count++;
        } else {
            f->passed = false;
            total_deductions += f->deduction;
            failed_count++;
            snprintf(f->details, sizeof(f->details), "Startup KAT not verified (%s) or health failures unlogged (%s).",
                     policy->conditioner_startup_kat_verified ? "verified" : "skipped",
                     policy->log_health_test_failures ? "logged" : "silent");
            snprintf(f->recommendation, sizeof(f->recommendation), "Execute startup Known Answer Tests on the hash conditioner and emit syslog audit trails.");
        }
    }

    report->passed_rules = passed_count;
    report->failed_rules = failed_count;
    report->total_deductions = total_deductions;
    if (total_deductions >= 100) {
        report->posture_score = 0;
    } else {
        report->posture_score = 100 - total_deductions;
    }

    return 0;
}
