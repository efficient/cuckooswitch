#include <stdlib.h>
#include <assert.h>

#include "conf_parser.h"

struct conf_item_entry {
    char *option;
    char *value;
    struct conf_item_entry *next;
};

struct conf_section_entry {
    char *section_name;
    struct conf_item_entry *item_head;
    struct conf_section_entry *next;
};

static 
void conf_items_free(struct conf_item_entry *item_head)
{
    if (item_head) {
        conf_items_free(item_head->next);
        free(item_head);
    }
}

static 
void conf_sections_free(struct conf_section_entry *section_head)
{
    if (section_head) {
        conf_sections_free(section_head->next);
        conf_items_free(section_head->item_head);
        free(section_head);
    }
}

static struct conf_item_entry *
get_conf_item(struct conf_section_entry *section, char *option)
{
    struct conf_item_entry *item = section->item_head;

    while (item) {
        if (!strcmp(item->option, option))
            return item;
        item = item->next;
    }
    return NULL;
}

static struct conf_section_entry *
get_conf_section(struct conf_parser *conf, char *section_name)
{
    struct conf_section_entry *section = conf->section_head;

    while (section) {
        if (!strcmp(section->section_name, section_name))
            return section;
        section = section->next;
    }
    return NULL;
}

struct conf_parser *
conf_parser_create(char *conf_filename)
{
    struct conf_parser *conf = (struct conf_parser *)malloc(sizeof(struct conf_parser));
    memset(conf, 0, sizeof(struct conf_parser)); 

    conf->file_data = get_file_data(conf_filename, &conf->file_size, 1); // add one byte for addtional '\n'
    if (!conf->file_data)
        goto conf_err;
    ((char*)conf->file_data)[conf->file_size] = '\n';

    struct conf_section_entry *section = NULL;
    char *p, *line, *next_line, *end, *section_name;
    int lineno = 0;

    p = (char*)conf->file_data;
    end = p + conf->file_size;

    while (p < end) {
        /*
         * get line
         */
        lineno++;
        while (*p == ' ' || *p == '\t' || *p == '\r') p++;

        line = p;
        while (*p != '\n' && p < end) {
            if (*p == '#') *p = '\0';
            p++;
        }
        *p = '\0';
        next_line = ++p;

        /*
         * parse line
         */
        p = line;
        if (*p == '\0') 
            goto conf_next;
        char* split = strchr(p, '=');
        if (!split && *p != '[')
            goto conf_reg;
        if (split && *p == '[')
            goto conf_err;

        if (split) {
        conf_reg:
            if (!section)
                goto conf_err;

            if (split) *split = '\0';
            char *option = trim_string(p);
            char *value = split ? trim_string(++split) : NULL;

            if (*option == '\0') 
                goto conf_err;
            if (get_conf_item(section, option))
                goto conf_err;

            struct conf_item_entry *item = (struct conf_item_entry *)malloc(sizeof(struct conf_item_entry));
            memset(item, 0, sizeof(struct conf_item_entry));

            item->option = option;
            item->value = value;
            item->next = section->item_head;
            section->item_head = item;
        } else {
            char *right = strchr(p, ']');
            if (!right) 
                goto conf_err;
            *right = '\0';

            p++;
            section_name = trim_string(p);
            if (*section_name == '\0') 
                goto conf_err;
            if (get_conf_section(conf, section_name))
                goto conf_err;
 
            section = (struct conf_section_entry *)malloc(sizeof(struct conf_section_entry));
            memset(section, 0, sizeof(struct conf_section_entry));

            section->section_name = section_name;
            section->next = conf->section_head;
            conf->section_head = section;
        }
    conf_next:
        p = next_line;
    }
    return conf;

conf_err:
    conf_parser_free(conf);
    return NULL;
}

void 
conf_parser_free(struct conf_parser *conf)
{
    if (conf->file_data) {
        conf_sections_free(conf->section_head);
        free_file_data(conf->file_data);
        conf->file_data = 0;
        conf->file_size = 0;
    }
}

char *
conf_parser_get_option_value(struct conf_parser *conf, char *section_name, char *option)
{
    struct conf_section_entry *section;
    struct conf_item_entry *item;

    section = get_conf_section(conf, section_name);
    if (section) {
        item = get_conf_item(section, option);
        return item ? item->value : NULL;
    }
    return NULL;
}
