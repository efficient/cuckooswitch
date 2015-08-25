#ifndef __CONF_PARSER_H__
#define __CONF_PARSER_H__

#include "utility.h"

struct conf_parser {
    void *file_data;
    uint32_t file_size;
    struct conf_section *section_head;
};

struct conf_parser *
conf_parser_create(char *conf_filename);

void 
conf_parser_free(struct conf_parser *conf);

char *
conf_parser_get_option_value(struct conf_parser *conf, char *section_name, char *option);

#endif
