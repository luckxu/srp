#ifndef __SRP_CONFIG_PROC_H__
#define __SRP_CONFIG_PROC_H__

typedef enum { e_error = 0, e_none, e_tag, e_cfg } conf_ret_t;

conf_ret_t get_string(char *line, char **key, char **value);

#endif