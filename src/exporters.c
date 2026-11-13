#include "exporters.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *severity_to_str(severity_t sev) {
    switch (sev) {
        case SEV_CRITICAL: return "CRITICAL";
        case SEV_HIGH:     return "HIGH";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_LOW:      return "LOW";
        default:           return "INFO";
    }
}

static const char *severity_to_sarif_level(severity_t sev) {
    switch (sev) {
        case SEV_CRITICAL:
        case SEV_HIGH:     return "error";
        case SEV_MEDIUM:   return "warning";
        case SEV_LOW:      return "note";
        default:           return "none";
    }
}

int export_audit_table(const audit_report_t *report, FILE *stream) {
    if (!report || !stream) return -1;

    fprintf(stream, "\n========================================================================================\n");
    fprintf(stream, " LOGIHERTZ CRYPTOGRAPHIC HARDWARE ENTROPY DAEMON - POSTURE AUDIT REPORT\n");
    fprintf(stream, " Policy: %s\n", report->policy_name);
    fprintf(stream, "========================================================================================\n");
    fprintf(stream, " %-12s | %-6s | %-8s | %-4s | %-42s\n", "RULE ID", "STATUS", "SEVERITY", "DED", "RULE NAME");
    fprintf(stream, "----------------------------------------------------------------------------------------\n");

    for (uint32_t i = 0; i < report->total_rules; i++) {
        const audit_finding_t *f = &report->findings[i];
        const char *status_str = f->passed ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m";
        fprintf(stream, " %-12s | %-15s | %-8s | -%-2u | %-42s\n",
            f->rule_id,
            status_str,
            severity_to_str(f->severity),
            f->passed ? 0 : f->deduction,
            f->rule_name);
    }

    fprintf(stream, "========================================================================================\n");
    fprintf(stream, " SUMMARY: Total Rules: %u | Passed: %u | Failed: %u | Deductions: -%u\n",
        report->total_rules, report->passed_rules, report->failed_rules, report->total_deductions);
    fprintf(stream, " POSTURE SCORE: \033[%sm%u / 100\033[0m [%s]\n",
        (report->posture_score >= 80) ? "32" : (report->posture_score >= 50 ? "33" : "31"),
        report->posture_score,
        (report->posture_score >= 80) ? "PASS" : "FAIL");
    fprintf(stream, "========================================================================================\n\n");

    return 0;
}

int export_audit_json(const audit_report_t *report, FILE *stream) {
    if (!report || !stream) return -1;

    fprintf(stream, "{\n");
    fprintf(stream, "  \"tool\": \"lh-entropy\",\n");
    fprintf(stream, "  \"policy_name\": \"%s\",\n", report->policy_name);
    fprintf(stream, "  \"posture_score\": %u,\n", report->posture_score);
    fprintf(stream, "  \"total_rules\": %u,\n", report->total_rules);
    fprintf(stream, "  \"passed_rules\": %u,\n", report->passed_rules);
    fprintf(stream, "  \"failed_rules\": %u,\n", report->failed_rules);
    fprintf(stream, "  \"total_deductions\": %u,\n", report->total_deductions);
    fprintf(stream, "  \"status\": \"%s\",\n", (report->posture_score >= 80) ? "PASS" : "FAIL");
    fprintf(stream, "  \"findings\": [\n");

    for (uint32_t i = 0; i < report->total_rules; i++) {
        const audit_finding_t *f = &report->findings[i];
        fprintf(stream, "    {\n");
        fprintf(stream, "      \"rule_id\": \"%s\",\n", f->rule_id);
        fprintf(stream, "      \"rule_name\": \"%s\",\n", f->rule_name);
        fprintf(stream, "      \"cwe_id\": \"%s\",\n", f->cwe_id);
        fprintf(stream, "      \"severity\": \"%s\",\n", severity_to_str(f->severity));
        fprintf(stream, "      \"deduction\": %u,\n", f->passed ? 0 : f->deduction);
        fprintf(stream, "      \"passed\": %s,\n", f->passed ? "true" : "false");
        fprintf(stream, "      \"details\": \"%s\",\n", f->details);
        fprintf(stream, "      \"recommendation\": \"%s\"\n", f->recommendation);
        fprintf(stream, "    }%s\n", (i + 1 < report->total_rules) ? "," : "");
    }

    fprintf(stream, "  ]\n");
    fprintf(stream, "}\n");
    return 0;
}

int export_audit_sarif(const audit_report_t *report, FILE *stream) {
    if (!report || !stream) return -1;

    fprintf(stream, "{\n");
    fprintf(stream, "  \"$schema\": \"https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json\",\n");
    fprintf(stream, "  \"version\": \"2.1.0\",\n");
    fprintf(stream, "  \"runs\": [\n");
    fprintf(stream, "    {\n");
    fprintf(stream, "      \"tool\": {\n");
    fprintf(stream, "        \"driver\": {\n");
    fprintf(stream, "          \"name\": \"lh-entropy\",\n");
    fprintf(stream, "          \"version\": \"0.1.0\",\n");
    fprintf(stream, "          \"informationUri\": \"https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-entropy-harvester\",\n");
    fprintf(stream, "          \"rules\": [\n");

    for (uint32_t i = 0; i < report->total_rules; i++) {
        const audit_finding_t *f = &report->findings[i];
        fprintf(stream, "            {\n");
        fprintf(stream, "              \"id\": \"%s\",\n", f->rule_id);
        fprintf(stream, "              \"name\": \"%s\",\n", f->rule_name);
        fprintf(stream, "              \"shortDescription\": { \"text\": \"%s\" },\n", f->rule_name);
        fprintf(stream, "              \"help\": { \"text\": \"%s\" },\n", f->recommendation);
        fprintf(stream, "              \"defaultConfiguration\": {\n");
        fprintf(stream, "                \"level\": \"%s\"\n", severity_to_sarif_level(f->severity));
        fprintf(stream, "              }\n");
        fprintf(stream, "            }%s\n", (i + 1 < report->total_rules) ? "," : "");
    }

    fprintf(stream, "          ]\n");
    fprintf(stream, "        }\n");
    fprintf(stream, "      },\n");
    fprintf(stream, "      \"results\": [\n");

    uint32_t printed_results = 0;
    for (uint32_t i = 0; i < report->total_rules; i++) {
        const audit_finding_t *f = &report->findings[i];
        if (!f->passed) {
            if (printed_results > 0) fprintf(stream, ",\n");
            fprintf(stream, "        {\n");
            fprintf(stream, "          \"ruleId\": \"%s\",\n", f->rule_id);
            fprintf(stream, "          \"level\": \"%s\",\n", severity_to_sarif_level(f->severity));
            fprintf(stream, "          \"message\": { \"text\": \"%s\" },\n", f->details);
            fprintf(stream, "          \"locations\": [\n");
            fprintf(stream, "            {\n");
            fprintf(stream, "              \"physicalLocation\": {\n");
            fprintf(stream, "                \"artifactLocation\": { \"uri\": \"%s\" }\n", report->policy_name);
            fprintf(stream, "              }\n");
            fprintf(stream, "            }\n");
            fprintf(stream, "          ]\n");
            fprintf(stream, "        }");
            printed_results++;
        }
    }
    if (printed_results > 0) fprintf(stream, "\n");

    fprintf(stream, "      ]\n");
    fprintf(stream, "    }\n");
    fprintf(stream, "  ]\n");
    fprintf(stream, "}\n");
    return 0;
}

int export_noise_analysis_table(const noise_analysis_result_t *res, FILE *stream) {
    if (!res || !stream) return -1;

    fprintf(stream, "\n===================================================================\n");
    fprintf(stream, " NIST SP 800-90B NOISE SOURCE STATISTICAL & HEALTH ANALYSIS\n");
    fprintf(stream, "===================================================================\n");
    fprintf(stream, " Total Noise Samples   : %u bytes\n", res->sample_count);
    fprintf(stream, " Shannon Entropy (H1)  : %.4f bits / byte\n", res->shannon_entropy_h1);
    fprintf(stream, " MCV Min-Entropy (Hinf): %.4f bits / byte (%.4f bits/bit)\n",
            res->mcv_min_entropy_h_inf, res->mcv_min_entropy_per_bit);
    fprintf(stream, " Most Probable Symbol  : p_max = %.4f, p_u(99%%) = %.4f\n",
            res->most_probable_p_max, res->upper_bound_p_u);
    fprintf(stream, " Lag-1 Autocorrelation : r1 = %+.4f (%s)\n",
            res->lag1_autocorrelation_r1, res->harmonic_coupling_detected ? "HARMONIC LEAK" : "Decoupled");
    fprintf(stream, " ADC Rail Saturation   : %s\n", res->rail_saturation_detected ? "DETECTED (Excessive Rails)" : "None");
    fprintf(stream, " Repetition Count Test : Cutoff = %u | Status: %s\n",
            res->rct_cutoff, res->rct_passed ? "\033[32mPASS\033[0m" : "\033[31mFAULT (Stuck-At)\033[0m");
    fprintf(stream, " Adaptive Prop. Test   : Cutoff = %u | Status: %s\n",
            res->apt_cutoff, res->apt_passed ? "\033[32mPASS\033[0m" : "\033[31mFAULT (Bias)\033[0m");
    fprintf(stream, " Overall Verdict       : %s\n", res->verdict);
    fprintf(stream, "===================================================================\n\n");
    return 0;
}

int export_noise_analysis_json(const noise_analysis_result_t *res, FILE *stream) {
    if (!res || !stream) return -1;

    fprintf(stream, "{\n");
    fprintf(stream, "  \"tool\": \"lh-entropy\",\n");
    fprintf(stream, "  \"subcommand\": \"analyze-noise\",\n");
    fprintf(stream, "  \"sample_count\": %u,\n", res->sample_count);
    fprintf(stream, "  \"shannon_entropy_h1\": %.6f,\n", res->shannon_entropy_h1);
    fprintf(stream, "  \"mcv_min_entropy_h_inf\": %.6f,\n", res->mcv_min_entropy_h_inf);
    fprintf(stream, "  \"mcv_min_entropy_per_bit\": %.6f,\n", res->mcv_min_entropy_per_bit);
    fprintf(stream, "  \"most_probable_p_max\": %.6f,\n", res->most_probable_p_max);
    fprintf(stream, "  \"upper_bound_p_u\": %.6f,\n", res->upper_bound_p_u);
    fprintf(stream, "  \"lag1_autocorrelation_r1\": %.6f,\n", res->lag1_autocorrelation_r1);
    fprintf(stream, "  \"rct_cutoff\": %u,\n", res->rct_cutoff);
    fprintf(stream, "  \"apt_cutoff\": %u,\n", res->apt_cutoff);
    fprintf(stream, "  \"rct_passed\": %s,\n", res->rct_passed ? "true" : "false");
    fprintf(stream, "  \"apt_passed\": %s,\n", res->apt_passed ? "true" : "false");
    fprintf(stream, "  \"harmonic_coupling_detected\": %s,\n", res->harmonic_coupling_detected ? "true" : "false");
    fprintf(stream, "  \"rail_saturation_detected\": %s,\n", res->rail_saturation_detected ? "true" : "false");
    fprintf(stream, "  \"verdict\": \"%s\"\n", res->verdict);
    fprintf(stream, "}\n");
    return 0;
}

int export_conditioned_block_table(const conditioned_block_t *block, FILE *stream) {
    if (!block || !stream) return -1;

    fprintf(stream, "\n===================================================================\n");
    fprintf(stream, " NIST SP 800-90B SHA-256 CONDITIONED SEED & KERNEL RNDADDENTROPY\n");
    fprintf(stream, "===================================================================\n");
    fprintf(stream, " Raw Bytes Consumed    : %u bytes\n", block->raw_bytes_consumed);
    fprintf(stream, " Credited Entropy Bits : %d bits (capped at 256)\n", block->credited_entropy_bits);
    fprintf(stream, " Conditioned Hash Hex  : ");
    for (int i = 0; i < 32; i++) {
        fprintf(stream, "%02x", block->digest[i]);
    }
    fprintf(stream, "\n");
    fprintf(stream, " RNDADDENTROPY Payload : entropy_count = %d, buf_size = %d\n",
            block->pool_info.entropy_count, block->pool_info.buf_size);
    fprintf(stream, " Kernel Injection Word : [0x%08x, 0x%08x, 0x%08x, 0x%08x...]\n",
            block->pool_info.buf[0], block->pool_info.buf[1],
            block->pool_info.buf[2], block->pool_info.buf[3]);
    fprintf(stream, "===================================================================\n\n");
    return 0;
}

int export_conditioned_block_json(const conditioned_block_t *block, FILE *stream) {
    if (!block || !stream) return -1;

    fprintf(stream, "{\n");
    fprintf(stream, "  \"tool\": \"lh-entropy\",\n");
    fprintf(stream, "  \"subcommand\": \"condition\",\n");
    fprintf(stream, "  \"raw_bytes_consumed\": %u,\n", block->raw_bytes_consumed);
    fprintf(stream, "  \"credited_entropy_bits\": %d,\n", block->credited_entropy_bits);
    fprintf(stream, "  \"conditioned_seed_hex\": \"");
    for (int i = 0; i < 32; i++) {
        fprintf(stream, "%02x", block->digest[i]);
    }
    fprintf(stream, "\",\n");
    fprintf(stream, "  \"rndaddentropy\": {\n");
    fprintf(stream, "    \"entropy_count\": %d,\n", block->pool_info.entropy_count);
    fprintf(stream, "    \"buf_size\": %d,\n", block->pool_info.buf_size);
    fprintf(stream, "    \"words\": [\n");
    for (int i = 0; i < 8; i++) {
        fprintf(stream, "      \"0x%08x\"%s\n", block->pool_info.buf[i], (i + 1 < 8) ? "," : "");
    }
    fprintf(stream, "    ]\n");
    fprintf(stream, "  }\n");
    fprintf(stream, "}\n");
    return 0;
}
