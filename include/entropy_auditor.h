#ifndef LH_ENTROPY_AUDITOR_H
#define LH_ENTROPY_AUDITOR_H

#include "entropy_types.h"

int audit_entropy_policy(const entropy_policy_t *policy, audit_report_t *report);

#endif /* LH_ENTROPY_AUDITOR_H */
