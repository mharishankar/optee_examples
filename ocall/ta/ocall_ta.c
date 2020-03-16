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

static TEE_Result go()
{
	uint32_t eorig;
	TEE_Result res;

	char *str = "Hello, OCALLs!";
	char buf[256];

	TEE_Param params[4];
	uint32_t pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE);

	params[0].memref.buffer = str;
	params[0].memref.size = strlen(str) + 1;

	params[1].value.a = 0xA;
	params[1].value.b = 0xB;

	params[2].memref.buffer = buf;
	params[2].memref.size = sizeof(buf);

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE, 0, pt, params, &eorig);
	printf("CA return value: 0x%x of %u\n", res, eorig);

	printf("Param 1: %u, %u\n", params[1].value.a, params[1].value.b);

	if (params[2].memref.buffer) {
		printf("Have buffer in param 2: %zu\n", params[2].memref.size);
		printf("%s\n", params[2].memref.buffer);
	}

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
