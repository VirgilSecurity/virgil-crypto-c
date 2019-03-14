#ifndef IOTELIC_SP_INTERFACE_H_INCLUDED
#define IOTELIC_SP_INTERFACE_H_INCLUDED

#include <crypto_mailbox_interface.h>

typedef void (*vscf_iot_crypto_result_cb)(uint16_t op_ip, uint16_t opcode, void *out_data, uint32_t len);

void
vs_iot_init_crypto_interface(vscf_iot_crypto_result_cb cb);

int32_t
vs_iot_execute_crypto_op(vscf_command_type_e opcode, void *in_data, size_t ilen, void *out_data, size_t out_buf_sz, size_t *olen);
#endif
