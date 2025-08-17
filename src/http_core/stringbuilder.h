#ifndef STRING_BUILDER_H
#define STRING_BUILDER_H

#include <stdbool.h>
#include <stddef.h>

typedef struct StringBuilder StringBuilder;

StringBuilder *string_builder_new(size_t size_hint);
void string_builder_free(StringBuilder *string_builder);

void string_builder_set_growth_rate(StringBuilder *string_builder, float growth_rate);

bool string_builder_append(StringBuilder *string_builder, const char *string);
bool string_builder_append_len(StringBuilder *string_builder, const char *string, size_t len);

const char *string_builder_get_string(StringBuilder *string_builder);
char *string_builder_to_string(StringBuilder *string_builder);
char *string_builder_to_string_and_free(StringBuilder *string_builder);

#endif
