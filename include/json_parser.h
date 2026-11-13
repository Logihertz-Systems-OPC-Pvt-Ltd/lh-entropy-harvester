#ifndef LH_JSON_PARSER_H
#define LH_JSON_PARSER_H

#include "entropy_types.h"

int parse_entropy_policy_json(const char *json_str, entropy_policy_t *policy);
int parse_entropy_policy_file(const char *filepath, entropy_policy_t *policy);

int parse_noise_buffer_json(const char *json_str, raw_noise_buffer_t *noise);
int parse_noise_buffer_file(const char *filepath, raw_noise_buffer_t *noise);

#endif /* LH_JSON_PARSER_H */
