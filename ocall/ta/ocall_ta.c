#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include <ocall_ta.h>

#include <pta_ocall.h>
#include <util.h>

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

TEE_TASessionHandle g_pta_ocall_session = NULL;

TEE_Result TEE_InvokeHostCommand(uint32_t cancellationRequestTimeout,
				uint32_t commandID, uint32_t paramTypes,
				TEE_Param params[TEE_NUM_PARAMS],
				uint32_t *returnOrigin)
{
	TEE_UUID uuid = PTA_UUID;

	const uint32_t pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INOUT,
		params ? TEE_PARAM_TYPE_MEMREF_INOUT : TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	TEE_Param rpc_params[4] = { 0 };

	uint32_t eorig;
	TEE_Result res;

	/* Open TA2TA session with the OCALL PTA, if necessary */
	if (!g_pta_ocall_session) {
		res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
			&g_pta_ocall_session, &eorig);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to open session to OCALL PTA: 0x%x", res);
			eorig = TEE_ORIGIN_COMMS;
			goto exit;
		}
	}

	/* Set up the TA interface for the OCALL PTA */
	rpc_params[0].value.a = commandID;
	if (params) {
		rpc_params[0].value.b = paramTypes;
		rpc_params[1].memref.buffer = params;
		rpc_params[1].memref.size = sizeof(params);
	}

	/* Send the OCALL request to the OCALL PTA */
	res = TEE_InvokeTACommand(g_pta_ocall_session, cancellationRequestTimeout,
		PTA_OCALL_SEND, pt, rpc_params, &eorig);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to invoke SEND on OCALL PTA: 0x%x", res);
		eorig = TEE_ORIGIN_TEE;
		goto exit;
	}

	/* Extract the OCALL return value and error origin */
	res = rpc_params[0].value.a;
	eorig = rpc_params[0].value.b;

exit:
	if (returnOrigin)
		*returnOrigin = eorig;
	return res;
}

static TEE_Result go()
{
	uint32_t eorig;
	TEE_Result res;

	res = TEE_InvokeHostCommand(TEE_TIMEOUT_INFINITE, 0, 0, NULL, &eorig);
	printf("CA return value: 0x%x of %u\n", res, eorig);

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
