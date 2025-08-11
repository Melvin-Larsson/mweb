#include "config_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cJSON.h"
#include <errno.h>
#include "string.h"
#include <assert.h>

#define APP_CONFIG_FILE_PATH_ENV_NAME "APP_CONFIG_PATH"
#define DEFAULT_CONFIG_FILE_NAME "config.json"

struct ConfigManager{
    cJSON *json;
};

static char *_load_file(const char *path);

ConfigManager *config_manager_load_from_file(const char *path){
    ConfigManager *cm = malloc(sizeof(ConfigManager));
    if(cm == NULL){
        return NULL;
    }
    char *file = _load_file(path);
    if(file == NULL){
        goto exit_cm;
    }

    cm->json = cJSON_Parse(file);
    free(file);
    if(cm->json == NULL){
        fprintf(stderr, "Failed to parse json\n");
        goto exit_cm;
    }

    return cm;

exit_cm:
    free(cm);
    return NULL;
}

ConfigManager *config_manager_load_from_appconfig(){
    char *path = getenv(APP_CONFIG_FILE_PATH_ENV_NAME);
    if(path != NULL){
        return config_manager_load_from_file(path);
    }

    char buff[1024];
    ssize_t size = readlink("/proc/self/exe", buff, sizeof(buff));
    if(size < 0){
        fprintf(stderr, "Unable to find config file: Reason: %s\n", strerror(errno));
        return NULL;
    }
    else if(size == sizeof(buff)){
        fprintf(stderr, "Unable to find config file: Reason: file path too long\n");
        return NULL;
    }
    buff[size] = 0;

    char *dir_ptr = buff;
    for(char *c = buff; *c; c++){
        if(*c == '/' || *c == '\\'){
            dir_ptr = c;
        }
    }
    *dir_ptr = '\0';
    if(strlen(DEFAULT_CONFIG_FILE_NAME) + strlen("/") + strlen(buff) + 1 > sizeof(buff)){
        fprintf(stderr, "Unable to find config file: Reason: file path too long\n");
        return NULL;
    }
    strcat(buff, "/");
    strcat(buff, DEFAULT_CONFIG_FILE_NAME);
    return config_manager_load_from_file(buff);
}

void config_manager_free(ConfigManager *cm){
    if(cm == NULL){
        return;
    }
    if(cm->json != NULL){
        cJSON_Delete(cm->json);
        cm->json = NULL;
    }
    free(cm);
}

const char *config_manager_get_str(ConfigManager *cm, const char *key, const char *default_value){
    const char *res;
    if(!config_manager_try_get_str(cm, key, &res)){
        return default_value; 
    }
    return res;
}

int config_manager_get_int(ConfigManager *cm, const char *key, int default_value){
    int res;
    if(!config_manager_try_get_int(cm, key, &res)){
        return default_value;
    }
    return res;
}

bool config_manager_try_get_str(ConfigManager *cm, const char *key, const char **result){
    assert(cm != NULL);
    assert(cm->json != NULL);
    assert(key != NULL);

    cJSON *prop = cJSON_GetObjectItemCaseSensitive(cm->json, key);
    if(prop == NULL || !cJSON_IsString(prop) || prop->valuestring == NULL){
        return false;
    }

    *result = prop->valuestring;
    return true;
}

bool config_manager_try_get_int(ConfigManager *cm, const char *key, int *result){
    assert(cm != NULL);
    assert(cm->json != NULL);
    assert(key != NULL);

    cJSON *prop = cJSON_GetObjectItemCaseSensitive(cm->json, key);
    if(prop == NULL || !cJSON_IsNumber(prop)){
        return false;
    }

    *result =  prop->valueint;
    return true;
}

static char *_load_file(const char *path){
    FILE *f = fopen(path, "rb");
    if(f == NULL){
        fprintf(stderr, "Failed to open file '%s'\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *result = malloc(fsize + 1);
    if(result == NULL){
        fprintf(stderr, "Unable to allocate memory\n");
        fclose(f);
        return NULL;
    }
    size_t size = fread(result, fsize, 1, f);
    fclose(f);

    if(size == 0){
        fprintf(stderr, "Failed to read file '%s'\n", path);
        free(result);
        return NULL;
    }

    result[fsize] = 0;

    return result;
}
