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
        switch(test_elements[i].type) {
            case SINGLE_KEY_RECIPIENT:
                TEST_CHECK_ (__parse_one_key_recipient (&test_elements[i]),
                             "%s", test_elements[i].name);
                break;
            case MULTIPLE_KEY_RECIPIENT:
                TEST_CHECK_ (__parse_multiple_key_recipients (&test_elements[i]),
                             "%s", test_elements[i].name);
                break;
            case PASSWORD_KEY_RECIPIENT:
                TEST_CHECK_ (__parse_password_recipient (&test_elements[i]),
                             "%s", test_elements[i].name);
                break;
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
    TEST_CHECK_ (__password_encryption (), "Password encryption");
    TEST_CHECK_ (__single_key_encryption (), "Single key encryption");
    TEST_CHECK_ (__multiple_keys_encryption (), "Multiple keys encryption");
}

TEST_LIST = {
        { "CMS parsing", cms_parsing },
        { "CMS write", cms_write },
        { NULL, NULL }
};