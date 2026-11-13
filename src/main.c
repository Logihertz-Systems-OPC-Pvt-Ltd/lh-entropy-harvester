#include "entropy_types.h"
#include "sp800_90b_health.h"
#include "sha256_conditioner.h"
#include "entropy_auditor.h"
#include "exporters.h"
#include "json_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LH_ENTROPY_VERSION "0.1.0"

static void print_version(void) {
    printf("lh-entropy %s\n", LH_ENTROPY_VERSION);
    printf("Logihertz Cryptographic Hardware Entropy Daemon & NIST SP 800-90B Health Tester\n");
    printf("Copyright 2026 Logihertz Systems (OPC) Private Limited\n");
    printf("Author: Sameer Tawade <ops@logihertz.com>\n");
}

static void print_help(const char *prog) {
    print_version();
    printf("\nUsage:\n");
    printf("  %s <subcommand> [options]\n\n", prog);
    printf("Subcommands:\n");
    printf("  scan <policy.json>                Audit TRNG security posture against 10 normative rules\n");
    printf("  analyze-noise <noise.json>        Run NIST SP 800-90B RCT, APT, MCV min-entropy & autocorrelation\n");
    printf("  condition <noise.json>            Condition raw noise via FIPS 180-4 SHA-256 for /dev/random\n");
    printf("  health-test --mode <mode>         Execute continuous health tester state machine verification\n");
    printf("  --version, -v                     Display version and maintainer information\n");
    printf("  --help, -h                        Display this command manual\n\n");
    printf("Options for 'scan':\n");
    printf("  --format <table|json|sarif>       Output formatting (default: table)\n");
    printf("  --output <filepath>               Write output report to file instead of stdout\n\n");
    printf("Options for 'analyze-noise':\n");
    printf("  --target-hmin <bits/byte>         Target min-entropy floor (default: 4.0)\n");
    printf("  --format <table|json>             Output formatting (default: table)\n");
    printf("  --output <filepath>               Write output to file instead of stdout\n\n");
    printf("Options for 'condition':\n");
    printf("  --hmin <bits/byte>                Assessed min-entropy per byte (default: 4.0)\n");
    printf("  --derating <factor>               Entropy credit derating factor (default: 0.50)\n");
    printf("  --format <table|json>             Output formatting (default: table)\n");
    printf("  --output <filepath>               Write output to file instead of stdout\n\n");
    printf("Options for 'health-test':\n");
    printf("  --mode <pass|stuck-fault|bias-fault> Mode to verify in RCT and APT state machines\n");
    printf("  --hmin <bits/byte>                Assessed min-entropy for cutoff calculation (default: 5.0)\n\n");
    printf("Examples:\n");
    printf("  %s scan fixtures/hardened_entropy_policy.json --format table\n", prog);
    printf("  %s analyze-noise fixtures/sample_sram_adc_noise.json --target-hmin 4.5\n", prog);
    printf("  %s condition fixtures/sample_sram_adc_noise.json --format json\n", prog);
    printf("  %s health-test --mode stuck-fault\n", prog);
}

static int handle_scan(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Error: 'scan' requires a policy JSON file argument.\n");
        fprintf(stderr, "Usage: lh-entropy scan <policy.json> [--format table|json|sarif] [--output <path>]\n");
        return 2;
    }

    const char *policy_file = argv[2];
    const char *format = "table";
    const char *output_file = NULL;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            format = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else {
            fprintf(stderr, "Unknown option for scan: %s\n", argv[i]);
            return 2;
        }
    }

    entropy_policy_t policy;
    if (parse_entropy_policy_file(policy_file, &policy) != 0) {
        fprintf(stderr, "Error: Failed to parse policy JSON file: %s\n", policy_file);
        return 2;
    }

    audit_report_t report;
    if (audit_entropy_policy(&policy, &report) != 0) {
        fprintf(stderr, "Error: Failed to evaluate policy security posture.\n");
        return 2;
    }

    FILE *out_stream = stdout;
    if (output_file) {
        out_stream = fopen(output_file, "w");
        if (!out_stream) {
            fprintf(stderr, "Error: Unable to open output file: %s\n", output_file);
            return 2;
        }
    }

    if (strcmp(format, "json") == 0) {
        export_audit_json(&report, out_stream);
    } else if (strcmp(format, "sarif") == 0) {
        export_audit_sarif(&report, out_stream);
    } else {
        export_audit_table(&report, out_stream);
    }

    if (output_file) {
        fclose(out_stream);
        printf("Report written to %s\n", output_file);
    }

    return (report.posture_score >= 80) ? 0 : 1;
}

static int handle_analyze_noise(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Error: 'analyze-noise' requires a noise sample JSON file.\n");
        fprintf(stderr, "Usage: lh-entropy analyze-noise <noise.json> [--target-hmin <bits>] [--format table|json]\n");
        return 2;
    }

    const char *noise_file = argv[2];
    double target_hmin = 4.0;
    const char *format = "table";
    const char *output_file = NULL;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--target-hmin") == 0 && i + 1 < argc) {
            target_hmin = strtod(argv[++i], NULL);
        } else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            format = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        }
    }

    raw_noise_buffer_t noise;
    if (parse_noise_buffer_file(noise_file, &noise) != 0) {
        fprintf(stderr, "Error: Failed to parse noise sample JSON file: %s\n", noise_file);
        return 2;
    }

    noise_analysis_result_t result;
    if (analyze_noise_samples(noise.samples, noise.count, target_hmin, &result) != 0) {
        fprintf(stderr, "Error: Noise analysis failed.\n");
        return 2;
    }

    FILE *out_stream = stdout;
    if (output_file) {
        out_stream = fopen(output_file, "w");
        if (!out_stream) {
            fprintf(stderr, "Error: Unable to open output file: %s\n", output_file);
            return 2;
        }
    }

    if (strcmp(format, "json") == 0) {
        export_noise_analysis_json(&result, out_stream);
    } else {
        export_noise_analysis_table(&result, out_stream);
    }

    if (output_file) {
        fclose(out_stream);
        printf("Noise analysis written to %s\n", output_file);
    }

    return (strcmp(result.verdict, "HEALTHY_TRNG_ENTROPY") == 0) ? 0 : 1;
}

static int handle_condition(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Error: 'condition' requires a noise sample JSON file.\n");
        fprintf(stderr, "Usage: lh-entropy condition <noise.json> [--hmin <bits>] [--derating <factor>] [--format table|json]\n");
        return 2;
    }

    /* 1. Run Startup KAT */
    if (!sha256_startup_kat()) {
        fprintf(stderr, "CRITICAL ERROR: FIPS 140-3 SHA-256 Startup KAT Failed!\n");
        return 1;
    }

    const char *noise_file = argv[2];
    double hmin = 4.0;
    double derating = 0.50;
    const char *format = "table";
    const char *output_file = NULL;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--hmin") == 0 && i + 1 < argc) {
            hmin = strtod(argv[++i], NULL);
        } else if (strcmp(argv[i], "--derating") == 0 && i + 1 < argc) {
            derating = strtod(argv[++i], NULL);
        } else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            format = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        }
    }

    raw_noise_buffer_t noise;
    if (parse_noise_buffer_file(noise_file, &noise) != 0) {
        fprintf(stderr, "Error: Failed to parse noise sample JSON file: %s\n", noise_file);
        return 2;
    }

    if (noise.count < 64) {
        fprintf(stderr, "Error: Insufficient noise samples (%u < 64 minimum for 2.0x compression ratio).\n", noise.count);
        return 1;
    }

    conditioned_block_t block;
    if (condition_entropy_block(noise.samples, noise.count, hmin, derating, &block) != 0) {
        fprintf(stderr, "Error: Conditioning failed.\n");
        return 1;
    }

    FILE *out_stream = stdout;
    if (output_file) {
        out_stream = fopen(output_file, "w");
        if (!out_stream) {
            fprintf(stderr, "Error: Unable to open output file: %s\n", output_file);
            return 2;
        }
    }

    if (strcmp(format, "json") == 0) {
        export_conditioned_block_json(&block, out_stream);
    } else {
        export_conditioned_block_table(&block, out_stream);
    }

    if (output_file) {
        fclose(out_stream);
        printf("Conditioned block written to %s\n", output_file);
    }

    return 0;
}

static int handle_health_test(int argc, char **argv) {
    const char *mode = "pass";
    double hmin = 5.0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode = argv[++i];
        } else if (strcmp(argv[i], "--hmin") == 0 && i + 1 < argc) {
            hmin = strtod(argv[++i], NULL);
        }
    }

    sp800_90b_health_t health;
    sp800_90b_health_init(&health, hmin, false);

    printf("===================================================================\n");
    printf(" NIST SP 800-90B HEALTH TEST STATE MACHINE VERIFICATION\n");
    printf(" Mode: %s | Assessed H_min: %.2f bits/byte | RCT Cutoff: %u | APT Cutoff: %u\n",
           mode, hmin, health.rct.cutoff_c_rct, health.apt.cutoff_c_apt);
    printf("===================================================================\n");

    if (strcmp(mode, "pass") == 0) {
        /* Feed healthy varying samples */
        for (uint32_t i = 0; i < 1024; i++) {
            uint8_t sample = (uint8_t)((i * 37 + 11) & 0xff);
            sp800_90b_health_test_sample(&health, sample);
        }
        printf(" RCT Fault Latched : %s\n", health.rct.fault_latched ? "TRUE (FAIL)" : "FALSE (PASS)");
        printf(" APT Fault Latched : %s\n", health.apt.fault_latched ? "TRUE (FAIL)" : "FALSE (PASS)");
        printf(" Overall Health    : %s\n", (health.fault_flags == 0) ? "\033[32mHEALTHY (PASS)\033[0m" : "\033[31mFAULT (FAIL)\033[0m");
        printf("===================================================================\n\n");
        return (health.fault_flags == 0) ? 0 : 1;
    } else if (strcmp(mode, "stuck-fault") == 0) {
        /* Feed repeated identical byte to exceed C_RCT */
        uint32_t needed = health.rct.cutoff_c_rct + 2;
        for (uint32_t i = 0; i < needed; i++) {
            sp800_90b_health_test_sample(&health, 0xaa);
        }
        printf(" RCT Fault Latched : %s\n", health.rct.fault_latched ? "\033[31mTRUE (STUCK-AT DETECTED)\033[0m" : "FALSE");
        printf(" APT Fault Latched : %s\n", health.apt.fault_latched ? "TRUE" : "FALSE");
        printf(" State Latch Check : %s\n", (health.fault_flags & ENTROPY_FAULT_RCT_STUCK_AT) ? "VERIFIED FAULT" : "MISSED FAULT");
        printf("===================================================================\n\n");
        return (health.fault_flags & ENTROPY_FAULT_RCT_STUCK_AT) ? 1 : 0;
    } else if (strcmp(mode, "bias-fault") == 0) {
        /* Feed biased samples in window to exceed C_APT */
        uint32_t needed = health.apt.cutoff_c_apt + 5;
        for (uint32_t i = 0; i < 512; i++) {
            uint8_t sample = (i < needed) ? 0x55 : (uint8_t)(i & 0xff);
            sp800_90b_health_test_sample(&health, sample);
        }
        printf(" RCT Fault Latched : %s\n", health.rct.fault_latched ? "TRUE" : "FALSE");
        printf(" APT Fault Latched : %s\n", health.apt.fault_latched ? "\033[31mTRUE (BIAS DETECTED)\033[0m" : "FALSE");
        printf(" State Latch Check : %s\n", (health.fault_flags & ENTROPY_FAULT_APT_STATISTICAL_BIAS) ? "VERIFIED FAULT" : "MISSED FAULT");
        printf("===================================================================\n\n");
        return (health.fault_flags & ENTROPY_FAULT_APT_STATISTICAL_BIAS) ? 1 : 0;
    } else {
        fprintf(stderr, "Error: Unknown health-test mode: %s\n", mode);
        return 2;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_help(argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0) {
        print_version();
        return 0;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_help(argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "scan") == 0) {
        return handle_scan(argc, argv);
    }

    if (strcmp(argv[1], "analyze-noise") == 0) {
        return handle_analyze_noise(argc, argv);
    }

    if (strcmp(argv[1], "condition") == 0) {
        return handle_condition(argc, argv);
    }

    if (strcmp(argv[1], "health-test") == 0) {
        return handle_health_test(argc, argv);
    }

    fprintf(stderr, "Unknown command: %s\n\n", argv[1]);
    print_help(argv[0]);
    return 2;
}
