#ifndef LH_EXPORTERS_H
#define LH_EXPORTERS_H

#include "entropy_types.h"
#include <stdio.h>

/* Audit Exporters */
int export_audit_table(const audit_report_t *report, FILE *stream);
int export_audit_json(const audit_report_t *report, FILE *stream);
int export_audit_sarif(const audit_report_t *report, FILE *stream);

/* Noise Analysis Exporters */
int export_noise_analysis_table(const noise_analysis_result_t *res, FILE *stream);
int export_noise_analysis_json(const noise_analysis_result_t *res, FILE *stream);

/* Conditioned Block Exporters */
int export_conditioned_block_table(const conditioned_block_t *block, FILE *stream);
int export_conditioned_block_json(const conditioned_block_t *block, FILE *stream);

#endif /* LH_EXPORTERS_H */
