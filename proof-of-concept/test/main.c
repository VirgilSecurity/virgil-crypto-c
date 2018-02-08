//
// Created by Roman Kutashenko on 2/8/18.
//

#include "acutest.h"
#include "test-data.h"
#include "stdbool.h"

static bool
__parse_one_key_recipient (test_data_element_t * test_data) {
    return false;
}

static bool
__parse_multiple_key_recipients (test_data_element_t * test_data) {
    return false;
}

static bool
__parse_password_recipient (test_data_element_t * test_data) {
    return false;
}

static void
cms_parsing() {
    int i;

    for (i = 0; i < test_elements_cnt; ++i) {
        bool res = false;
        switch(test_elements[i].type) {
            case SINGLE_KEY_RECIPIENT:
                res = __parse_one_key_recipient (&test_elements[i]);
                break;
            case MULTIPLE_KEY_RECIPIENT:
                res = __parse_multiple_key_recipients (&test_elements[i]);
                break;
            case PASSWORD_KEY_RECIPIENT:
                res = __parse_password_recipient (&test_elements[i]);
                break;
        }

        if (!TEST_CHECK (res)) {
            TEST_MSG("%s\n\n", test_elements[i].name);
        }
    }
}

static bool
__password_encryption () {
    return false;
}

static bool
__single_key_encryption () {
    return false;
}

static bool
__multiple_keys_encryption () {
    return false;
}

static void
cms_write() {
    if (!TEST_CHECK (__password_encryption ())) {
        TEST_MSG("Password encryption\n\n");
    }

    if (!TEST_CHECK (__single_key_encryption ())) {
        TEST_MSG("Single key encryption\n\n");
    }

    if (!TEST_CHECK (__multiple_keys_encryption ())) {
        TEST_MSG("Multiple keys encryption\n\n");
    }
}

TEST_LIST = {
        { "CMS parsing", cms_parsing },
        { "CMS write", cms_write },
        { NULL, NULL }
};