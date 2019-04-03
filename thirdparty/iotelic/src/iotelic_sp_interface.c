#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <iotelic_sp_interface.h>
#include <mailbox/mailbox.h>
#include <common/iot_errno.h>
#include <iot_module_api.h>
#include <os_mem_api.h>
#include <os_lock_api.h>
#include <os_event_api.h>
#include <iot_io_api.h>
#include <iot_task_api.h>

#define MB_RCV_EVNT 1

static void
mb_task_event_handle(iot_task_h task_h, uint32_t event);
static void
mb_task_msg_handle(iot_task_h task_h, iot_task_msg_t *msg);
static void
mb_task_msg_cancel(iot_task_h task_h, iot_task_msg_t *msg);

typedef struct _safe_op_id_counter_s {
    os_mutex_h blocked;
    uint16_t op_id_counter;
} safe_op_id_counter_t;

typedef struct mailbox_exch_ctx_s {
    os_mutex_h  blocked;
    iot_task_h  handle;
    os_event_h  event;
    vscf_iot_crypto_result_cb user_result_cb;
    safe_op_id_counter_t *op_id_counter;
} mailbox_exch_ctx_t;

static mailbox_exch_ctx_t *exch_ctx = NULL;

static iot_task_config_t iot_mb_task_config = {
        .stack_size       = 0,
        .task_prio        = 8,
        .msg_size         = sizeof(size_t),
        .msg_cnt          = 8,
        .queue_cnt        = 1,
        .queue_cfg[0].quota = 0,
        .task_event_func  = mb_task_event_handle,
        .msg_exe_func     = mb_task_msg_handle,
        .msg_cancel_func  = mb_task_msg_cancel,
};

static safe_op_id_counter_t *
init_safe_op_id_counter() {
    safe_op_id_counter_t *obj;
    obj = (safe_op_id_counter_t*)os_mem_malloc(IOT_DRIVER_MID,
                                           sizeof(safe_op_id_counter_t));
    if(NULL == obj) {
        IOT_ASSERT(0);
        return NULL;
    }

    obj->blocked = os_create_mutex(IOT_DRIVER_MID);

    if(obj->blocked == NULL){
        IOT_ASSERT(0);
        os_mem_free(obj);
        return NULL;
    }

    return obj;

}

static uint16_t
get_safe_op_id_counter(safe_op_id_counter_t *obj) {
    uint16_t val;
    os_acquire_mutex(obj->blocked);
    val = obj->op_id_counter;
    os_release_mutex(obj->blocked);
    return val;
}

static void
inc_safe_op_id_counter(safe_op_id_counter_t *obj) {
    os_acquire_mutex(obj->blocked);
    obj->op_id_counter++;
    os_release_mutex(obj->blocked);
}

static void
deinit_safe_op_id_counter(safe_op_id_counter_t *obj) {
    os_delete_mutex(obj->blocked);
    os_mem_free(obj);
}

static void
crypto_result_blocked_op_cb(uint16_t op_ip, uint16_t opcode, void *out_data, uint32_t len) {
    os_set_event(exch_ctx->event);
}

static void
mb_receive_cb(void) {
    iot_mb_mask();
    os_set_task_event_with_v_from_isr(
            iot_task_get_os_task_h(exch_ctx->handle), MB_RCV_EVNT);
}

static void
mb_task_event_handle(iot_task_h task_h, uint32_t event) {
    (void)task_h;
    if(MB_RCV_EVNT & event) {
        uint32_t i;
        mailbox_cmd_t *cmd = 0;
        size_t addr;
        i = iot_mb_get_read_space();
        while (i) {
            if (ERR_OK == iot_mb_read(&addr)) {
                cmd = (mailbox_cmd_t *)addr;
                exch_ctx->user_result_cb(cmd->op_id, cmd->opcode, cmd->out_data, cmd->olen);
            }
            i--;
        }

        /* enable mailbox again*/
        iot_mb_unmask();
    }
    return;
}

static void
mb_task_msg_handle(iot_task_h task_h, iot_task_msg_t *msg)  {

}

static void
mb_task_msg_cancel(iot_task_h task_h, iot_task_msg_t *msg) {

}

static
int32_t create_mb_iot_task(vscf_iot_crypto_result_cb cb) {

    exch_ctx->event = os_create_event(IOT_DRIVER_MID, false);
    if(exch_ctx->event == NULL){
        IOT_ASSERT(0);
        goto out;
    }

    /* create mailbox task */
    exch_ctx->handle  = iot_task_create(IOT_DRIVER_MID, &iot_mb_task_config);
    if(exch_ctx->handle == NULL) {
        iot_printf("[AP]Error mailbox iot_task created\n");
        goto out;
    }

    iot_printf("[AP]mailbox iot_task is created...\n");

    exch_ctx->user_result_cb = cb;

    return ERR_OK;
out:
    os_delete_event(exch_ctx->event);
    return -ERR_FAIL;
}

static
void delete_mb_iot_task() {
    os_delete_event(exch_ctx->event);
    iot_task_delete(exch_ctx->handle);
}

const char *
iotelic_version(void) {
    return "0.1.0";
}

int32_t
vs_iot_init_crypto_interface() {
    if(NULL != exch_ctx) {
        return -ERR_EXIST;
    }

    exch_ctx = (mailbox_exch_ctx_t*)os_mem_malloc(IOT_DRIVER_MID,
                                  sizeof(mailbox_exch_ctx_t));
    if (exch_ctx == NULL) {
        iot_printf("[AP]%s:memory malloc fail.\n", __FUNCTION__);
        return -ERR_NOMEM;
    }

    memset(exch_ctx, 0, sizeof(mailbox_exch_ctx_t));

    iot_mb_init();

    if (ERR_OK != iot_mb_open(mb_receive_cb)){
        iot_printf("[AP]%s:fail to open mailbox...\n", __FUNCTION__);
        goto out;
    }

    exch_ctx->blocked = os_create_mutex(IOT_DRIVER_MID);
    if(exch_ctx->blocked == NULL){
        IOT_ASSERT(0);
        goto out;
    }

    exch_ctx->op_id_counter = init_safe_op_id_counter();
    if(NULL != exch_ctx->op_id_counter ){  //-V547
        return ERR_OK;
    }

    deinit_safe_op_id_counter(exch_ctx->op_id_counter);

    os_delete_mutex(exch_ctx->blocked);
out:
    os_mem_free(exch_ctx);
    exch_ctx = NULL;

    return -ERR_FAIL;
}

void
vs_iot_deinit_crypto_interface(void) {

    if(NULL == exch_ctx) {
        return;
    }

    iot_mb_close();
    deinit_safe_op_id_counter(exch_ctx->op_id_counter);

    os_delete_event(exch_ctx->event);
    os_delete_mutex(exch_ctx->blocked);

    os_mem_free(exch_ctx);
    exch_ctx = NULL;
}

int32_t
vs_iot_execute_crypto_op(vscf_command_type_e opcode, void *in_data, size_t ilen, void *out_data, size_t out_buf_sz, size_t *olen) {

    vs_iot_init_crypto_interface();

    if(NULL == exch_ctx) {
        return -ERR_NOT_READY;
    }

    os_acquire_mutex(exch_ctx->blocked);


    if(ERR_OK != create_mb_iot_task(crypto_result_blocked_op_cb)) {
        return -ERR_FAIL;
    }


    mailbox_cmd_t *cmd = os_mem_malloc(IOT_DRIVER_MID, sizeof(mailbox_cmd_t));
    if(NULL == cmd) {
        return -ERR_NOMEM;
    }

    cmd->opcode = opcode;
    cmd->in_data = in_data;
    cmd->ilen = ilen;
    cmd->out_data = out_data;
    cmd->out_buf_sz = out_buf_sz;
    cmd->olen = 0;
    cmd->op_id = get_safe_op_id_counter(exch_ctx->op_id_counter);
    inc_safe_op_id_counter(exch_ctx->op_id_counter);

    iot_mb_send(IPC_SECCPU_ID, (size_t)cmd);

    os_wait_event(exch_ctx->event, MAX_TIME);

    *olen = cmd->olen;
    int32_t result = cmd->result;
    os_mem_free(cmd);

    delete_mb_iot_task();

    os_release_mutex(exch_ctx->blocked);

    return result;
}
