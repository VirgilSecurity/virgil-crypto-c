#ifndef IOTELIC_SP_INTERFACE_H_INCLUDED
#define IOTELIC_SP_INTERFACE_H_INCLUDED

typedef void (*vscf_iot_crypto_result_cb)(uint16_t op_ip, uint16_t opcode, void *out_data, uint32_t len);

void
vscf_iot_init_crypto_interface(vscf_iot_crypto_result_cb cb);

int32_t
vscf_iot_execute_crypto_op(uint16_t opcode, void *in_data, uint32_t ilen, void *out_data, uint32_t out_buf_sz);
#endif