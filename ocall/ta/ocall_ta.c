#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include <ocall_ta.h>

#include <pta_ocall.h>

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4],
			    void **sess_ctx)
{
	(void)param_types;
	(void)params;
	(void)sess_ctx;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)sess_ctx;
}

static TEE_Result go()
{
	TEE_UUID uuid = PTA_UUID;
	TEE_TASessionHandle s;
	uint32_t eorig;
	TEE_Result res;

	const uint32_t pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	uint32_t ca_cmd_id;
	uint32_t ca_num_params;

	TEE_Param ca_params[4];
	size_t ca_params_size;

	uint32_t ca_cmd_ret;
	uint32_t ca_cmd_ret_origin;

	TEE_Param rpc_params[4] = { 0 };

	/* Open TA2TA session with the OCALL PTA */
	res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &s, &eorig);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open session to OCALL PTA: 0x%x", res);
		return res;
	}

	ca_cmd_id = 0;
	ca_num_params = 4;
	ca_params_size = sizeof(*ca_params) * ca_num_params;
	memset(ca_params, 0, ca_params_size);

	rpc_params[0].value.a = ca_cmd_id;
	rpc_params[0].value.b = ca_num_params;
	rpc_params[1].memref.buffer = ca_params;
	rpc_params[1].memref.size = ca_params_size;

	res = TEE_InvokeTACommand(s, TEE_TIMEOUT_INFINITE, PTA_OCALL_SEND, pt,
		rpc_params, &eorig);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to invoke SEND on OCALL PTA: 0x%x", res);
		return res;
	}

	ca_cmd_ret = rpc_params[0].value.a;
	ca_cmd_ret_origin = rpc_params[0].value.b;

	printf("CA return value: 0x%x of %u\n", ca_cmd_ret, ca_cmd_ret_origin);

	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
			    uint32_t cmd_id, uint32_t param_types, TEE_Param params[4])
{
	(void)sess_ctx;
	(void)param_types;
	(void)params;

	switch (cmd_id)
	{
	case TA_OCALL_CMD_TEST:
		return go();
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
