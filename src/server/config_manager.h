#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <stdbool.h>

typedef struct ConfigManager ConfigManager;

ConfigManager *config_manager_load_from_file(const char *file);
ConfigManager *config_manager_load_from_appconfig();
void config_manager_free(ConfigManager *cm);

const char *config_manager_get_str(ConfigManager *cm, const char *key, const char *default_value);
int config_manager_get_int(ConfigManager *cm, const char *key, int default_value);

bool config_manager_try_get_str(ConfigManager *cm, const char *key, const char **result);
bool config_manager_try_get_int(ConfigManager *cm, const char *key, int *result);

#endif
