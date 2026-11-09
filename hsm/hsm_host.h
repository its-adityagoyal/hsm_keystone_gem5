#ifndef _HSM_HOST_H_
#define _HSM_HOST_H_

#include "hsm_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

int hsm_host_init(const char* eapp_path, const char* runtime_path);
int hsm_host_send_command(const hsm_req_t* req, hsm_resp_t* resp);
int hsm_host_destroy(void);

#ifdef __cplusplus
}
#endif

#endif /* _HSM_HOST_H_ */
