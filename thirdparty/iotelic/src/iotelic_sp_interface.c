#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <iotelic_sp_interface.h>
#include <mailbox/mailbox.h>
#include <common/iot_errno.h>

const char *iotelic_version(void) {
    return "0.1.0";
}

typedef struct mailbox_exch_ctx_s {
    bool is_initialized;
    bool is_blocked;
    bool is_result;
    vscf_iot_crypto_result_cb user_result_cb;
    uint16_t op_id_counter;
} mailbox_exch_ctx_t;

static mailbox_exch_ctx_t exch_ctx = {0};

static void
crypto_result_blocked_op_cb(uint16_t op_ip, uint16_t opcode, void *out_data, uint32_t len){
    exch_ctx.is_result = true;
}

static void
mb_receive_cb(void) {
    uint32_t i;
    mailbox_cmd_t *cmd = 0;
    size_t addr = (size_t)cmd;
    i = iot_mb_get_read_space();

    while (i) {
        if (ERR_OK == iot_mb_read(&addr)) {
            cmd = (mailbox_cmd_t *)addr;

            if(exch_ctx.is_blocked) {
                crypto_result_blocked_op_cb(cmd->op_id, cmd->opcode, cmd->out_data, cmd->olen);
            } else if(NULL != exch_ctx.user_result_cb){
                exch_ctx.user_result_cb(cmd->op_id, cmd->opcode, cmd->out_data, cmd->olen);
            }
        }
        i--;
    }
}

void
vs_iot_init_crypto_interface(vscf_iot_crypto_result_cb cb){

    if(exch_ctx.is_initialized) {
        return;
    }

    memset(&exch_ctx, 0, sizeof(mailbox_exch_ctx_t));
    exch_ctx.is_initialized = true;
    exch_ctx.user_result_cb = cb;

    iot_mb_init();
    iot_mb_open(mb_receive_cb);
}

int32_t
vs_iot_execute_crypto_op(vscf_command_type_e opcode, void *in_data, size_t ilen, void *out_data, size_t out_buf_sz, size_t *olen) {

    if(!exch_ctx.is_initialized) {
        return -ERR_NOT_READY;
    }

    //TODO: Need to implement atomic crypto operations and queue. Change is_blocked flag to mutex
    while (exch_ctx.is_blocked);
    exch_ctx.is_blocked = true;

    mailbox_cmd_t cmd;
    cmd.opcode = opcode;
    cmd.in_data = in_data;
    cmd.ilen = ilen;
    cmd.out_data = out_data;
    cmd.out_buf_sz = out_buf_sz;
    cmd.olen = 0;
    cmd.op_id = exch_ctx.op_id_counter++;

    //TODO: Implement os messages for notifying about end crypto op
    exch_ctx.is_result = false;

    iot_mb_send(1, (size_t)&cmd);

    while(!exch_ctx.is_result);
    *olen = cmd.olen;
    exch_ctx.is_blocked = false;

    return cmd.result;
}
