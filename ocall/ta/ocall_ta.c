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

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)sess_ctx;
}

/* ECALL has no parameters, OCALL has no parameters */
static TEE_Result test1(uint32_t param_types,
		        TEE_Param __unused params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	
	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE, TA_OCALL_CA_CMD_TEST_1,
		0, NULL, &eorig);
	if (res != TEE_SUCCESS)
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);

	return res;
}

/* ECALL has no parameters, OCALL has one [IN] VALUE parameter */
static TEE_Result test2(uint32_t param_types,
		        TEE_Param __unused params[TEE_NUM_PARAMS])
{
	TEE_Param ocall_params[TEE_NUM_PARAMS];

	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	const uint32_t ocall_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	ocall_params[0].value.a = 0xA;
	ocall_params[0].value.b = 0xB;

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE, TA_OCALL_CA_CMD_TEST_2,
		ocall_param_types, ocall_params, &eorig);
	if (res != TEE_SUCCESS)
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);

	return res;
}

/* ECALL has no parameters, OCALL has one [IN] MEMREF parameter */
static TEE_Result test3(uint32_t param_types,
		        TEE_Param __unused params[TEE_NUM_PARAMS])
{
	TEE_Param ocall_params[TEE_NUM_PARAMS];

	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	const uint32_t ocall_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	const char *msg = "This string was sent by the TA";

	ocall_params[0].memref.buffer = (void *)msg;
	ocall_params[0].memref.size = strlen(msg) + 1;

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE, TA_OCALL_CA_CMD_TEST_3,
		ocall_param_types, ocall_params, &eorig);
	if (res != TEE_SUCCESS)
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);

	return res;
}

/* ECALL has no parameters, OCALL has one [OUT] VALUE parameter */
static TEE_Result test4(uint32_t param_types,
		        TEE_Param __unused params[TEE_NUM_PARAMS])
{
	TEE_Param ocall_params[TEE_NUM_PARAMS];

	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	const uint32_t ocall_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE, TA_OCALL_CA_CMD_TEST_4,
		ocall_param_types, ocall_params, &eorig);
	if (res != TEE_SUCCESS)
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);

	printf("Output values: %u, %u\n", ocall_params[0].value.a,
		ocall_params[0].value.b);

	return res;
}

/* ECALL has no parameters, OCALL has one [OUT] MEMREF parameter */
static TEE_Result test5(uint32_t param_types,
		        TEE_Param __unused params[TEE_NUM_PARAMS])
{
	TEE_Param ocall_params[TEE_NUM_PARAMS];

	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	const uint32_t ocall_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	char buf[256];

	ocall_params[0].memref.buffer = buf;
	ocall_params[0].memref.size = sizeof(buf);

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE, TA_OCALL_CA_CMD_TEST_5,
		ocall_param_types, ocall_params, &eorig);
	if (res != TEE_SUCCESS)
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);

	printf("Output string: \"%s\"\n", (char *)ocall_params[0].memref.buffer);
	printf("Output size: %u\n", ocall_params[0].memref.size);

	return res;
}

/* ECALL has no parameters, OCALL has one [INOUT] VALUE parameter */
static TEE_Result test6(uint32_t param_types,
		        TEE_Param __unused params[TEE_NUM_PARAMS])
{
	TEE_Param ocall_params[TEE_NUM_PARAMS];

	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	const uint32_t ocall_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	ocall_params[0].value.a = 0xC;
	ocall_params[0].value.b = 0xD;

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE, TA_OCALL_CA_CMD_TEST_6,
		ocall_param_types, ocall_params, &eorig);
	if (res != TEE_SUCCESS)
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);

	printf("Output values: %u, %u\n", ocall_params[0].value.a,
		ocall_params[0].value.b);

	return res;
}

/* ECALL has no parameters, OCALL has one [INOUT] MEMREF parameter */
static TEE_Result test7(uint32_t param_types,
		        TEE_Param __unused params[TEE_NUM_PARAMS])
{
	TEE_Param ocall_params[TEE_NUM_PARAMS];

	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	const uint32_t ocall_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	char buf[256];
	const char *msg = "This string was sent by the TA";

	memcpy(buf, msg, strlen(msg) + 1);

	ocall_params[0].memref.buffer = buf;
	ocall_params[0].memref.size = sizeof(buf);

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE, TA_OCALL_CA_CMD_TEST_7,
		ocall_param_types, ocall_params, &eorig);
	if (res != TEE_SUCCESS)
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);

	printf("Output string: \"%s\"\n", (char *)ocall_params[0].memref.buffer);
	printf("Output size: %u\n", ocall_params[0].memref.size);

	return res;
}

/*
 * ECALL has no parameters, OCALL has:
 * - One [INPUT] VALUE parameter
 * - One [INOUT] VALUE parameter
 * - One [INPUT] MEMREF parameter
 * - One [INOUT] MEMREF parameter
 */
static TEE_Result test8(uint32_t param_types,
		        TEE_Param __unused params[TEE_NUM_PARAMS])
{
	TEE_Param ocall_params[TEE_NUM_PARAMS];

	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	const uint32_t ocall_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INOUT
	);

	char buf1[128];
	char buf2[128];

	const char *msg1 = "This string was sent by the TA";
	const char *msg2 = "The TA thinks this is a fun riddle";

	memcpy(buf1, msg1, strlen(msg1) + 1);
	memcpy(buf2, msg2, strlen(msg2) + 1);

	ocall_params[0].value.a = 0x1;
	ocall_params[0].value.b = 0x2;

	ocall_params[1].value.a = 0xA;
	ocall_params[1].value.b = 0xB;
 
	ocall_params[2].memref.buffer = buf1;
	ocall_params[2].memref.size = sizeof(buf1);

	ocall_params[3].memref.buffer = buf2;
	ocall_params[3].memref.size = sizeof(buf2);

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE, TA_OCALL_CA_CMD_TEST_8,
		ocall_param_types, ocall_params, &eorig);
	if (res != TEE_SUCCESS)
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);

	printf("Output values: %u, %u\n", ocall_params[1].value.a,
		ocall_params[1].value.b);

	printf("Output string: \"%s\"\n", (char *)ocall_params[3].memref.buffer);
	printf("Output size: %u\n", ocall_params[3].memref.size);

	return res;
}

/*
 * ECALL has no parameters, OCALL has:
 * - One [INPUT] VALUE parameter
 * - One [INOUT] VALUE parameter
 * - One [INPUT] MEMREF parameter
 * - One [INOUT] MEMREF parameter
 */
static TEE_Result test9(uint32_t param_types,
		        TEE_Param __unused params[TEE_NUM_PARAMS])
{
	TEE_Param ocall_params[TEE_NUM_PARAMS];

	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INOUT
	);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	const uint32_t ocall_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INOUT
	);

	if (!params[2].memref.buffer || !params[3].memref.buffer) {
		printf("\tNo buffer(s)\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	char buf1[128];
	char buf2[128];

	const char *msg1 = "This string was sent by the TA";
	const char *msg2 = "The TA thinks this is a fun riddle";

	printf("\tInput values: %u, %u\n", params[0].value.a,
		params[0].value.b);

	printf("\tInout values: %u, %u\n", params[1].value.a,
		params[1].value.b);

	printf("\tInput string: %s\n", (char *)params[2].memref.buffer);
	printf("\tInput size: %u\n", params[2].memref.size);

	printf("\tInout string: %s\n", (char *)params[3].memref.buffer);
	printf("\tInout size: %u\n", params[3].memref.size);

	/* Set ECALL INOUT parameters */
	params[1].value.a = 0xE;
	params[1].value.b = 0xF;

	params[3].memref.size = strlen(msg2) + 1;
	memcpy(params[3].memref.buffer, msg2, params[3].memref.size);

	memcpy(buf1, msg1, strlen(msg1) + 1);
	memcpy(buf2, msg2, strlen(msg2) + 1);

	/* Set OCALL INPUT/INOUT parameters */
	ocall_params[0].value.a = 0x1;
	ocall_params[0].value.b = 0x2;

	ocall_params[1].value.a = 0xA;
	ocall_params[1].value.b = 0xB;
 
	ocall_params[2].memref.buffer = buf1;
	ocall_params[2].memref.size = sizeof(buf1);

	ocall_params[3].memref.buffer = buf2;
	ocall_params[3].memref.size = sizeof(buf2);

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE, TA_OCALL_CA_CMD_TEST_9,
		ocall_param_types, ocall_params, &eorig);
	if (res != TEE_SUCCESS)
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);

	printf("Output values: %u, %u\n", ocall_params[1].value.a,
		ocall_params[1].value.b);

	printf("Output string: \"%s\"\n", (char *)ocall_params[3].memref.buffer);
	printf("Output size: %u\n", ocall_params[3].memref.size);

	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	(void)sess_ctx;

	printf("ECALL: %u\n", cmd_id);

	switch (cmd_id)
	{
	case TA_OCALL_CMD_TEST_1:
		return test1(param_types, params);
	case TA_OCALL_CMD_TEST_2:
		return test2(param_types, params);
	case TA_OCALL_CMD_TEST_3:
		return test3(param_types, params);
	case TA_OCALL_CMD_TEST_4:
		return test4(param_types, params);
	case TA_OCALL_CMD_TEST_5:
		return test5(param_types, params);
	case TA_OCALL_CMD_TEST_6:
		return test6(param_types, params);
	case TA_OCALL_CMD_TEST_7:
		return test7(param_types, params);
	case TA_OCALL_CMD_TEST_8:
		return test8(param_types, params);
	case TA_OCALL_CMD_TEST_9:
		return test9(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
