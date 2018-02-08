#ifndef TEST_DATA_H
#define TEST_DATA_H

#define SINGLE_KEY_RECIPIENT	0
#define MULTIPLE_KEY_RECIPIENT	1
#define PASSWORD_KEY_RECIPIENT	2

typedef struct {
	unsigned char *data;
	unsigned int data_sz;
	const char *name;
	unsigned char type;
} test_data_element_t;

extern test_data_element_t test_elements[];
extern unsigned int test_elements_cnt;

#endif // TEST_DATA_H