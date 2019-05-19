#include <stdlib.h>
#include <assert.h>
#include "config.h"
#include <ctype.h>

conf_ret_t get_string(char *line, char **key, char **value) {
    assert(line && key && value);
    *key = *value = NULL;
    while(isspace(*line) && *line != '\0')
        line++;
    //注释或空行
    if(*line == '#' || *line == '\0')
        return e_none;
    //tag标识
    if(*line == '[') {
        *key = ++line;
        while(isalnum(*line)) {
            line++;
        }
        *line = '\0';
        return e_tag;
    }
    //普通配置
    *key = line;
    while(!isspace(*line) && *line != '=')
        line++;
    //没有配置值
    if(*line == '\0')
        return e_error;
    *line++ = '\0';
    //路过空格或等号
    while(isspace(*line) || *line == '=')
        line++;
    //配置值为空
    if(*line == '\0')
        return e_error;
    *value = line;
    while(!isspace(*line))
        line++;
    *line = '\0';
    return e_cfg;
}
