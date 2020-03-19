/*
 * Copyright (c) 2020, Microsoft Corporation
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>
#include <tee_client_api_extensions.h>

#include <ocall_ta.h>

static void print_uuid(TEEC_UUID *uuid)
{
	printf("\tClient: %x-%x-%x-%x%x-%x%x%x%x%x%x\n",
		uuid->timeLow,
		uuid->timeMid,
		uuid->timeHiAndVersion,
		uuid->clockSeqAndNode[0],
		uuid->clockSeqAndNode[1],
		uuid->clockSeqAndNode[2],
		uuid->clockSeqAndNode[3],
		uuid->clockSeqAndNode[4],
		uuid->clockSeqAndNode[5],
		uuid->clockSeqAndNode[6],
		uuid->clockSeqAndNode[7]);
}

TEEC_Result ocall_handler(void *context, TEEC_UUID *taUUID, uint32_t commandId,
			  uint32_t paramTypes,
			  TEEC_Parameter params[TEEC_CONFIG_PAYLOAD_REF_COUNT])
{
	printf("OCALL: %u\n", commandId);
	print_uuid(taUUID);

	char *msg = "This string was sent by the CA";

	switch (commandId)
	{
	case TA_OCALL_CA_CMD_TEST_1:
		printf("\tOK\n");
		break;
	case TA_OCALL_CA_CMD_TEST_2:
		printf("\tInput values: %u, %u\n", params[0].value.a,
			params[0].value.b);
		printf("\tOK\n");
		break;
	case TA_OCALL_CA_CMD_TEST_3:
		printf("\tInput string: %s\n", (char *)params[0].tmpref.buffer);
		printf("\tInput size: %zu\n", params[0].tmpref.size);
		printf("\tOK\n");
		break;
	case TA_OCALL_CA_CMD_TEST_4:
		params[0].value.a = 0x1;
		params[0].value.b = 0x2;
		printf("\tOK\n");
		break;
	case TA_OCALL_CA_CMD_TEST_5:
		if (!params[0].tmpref.buffer) {
			printf("\tNo buffer\n");
			return TEEC_ERROR_BAD_PARAMETERS;
		}
		printf("\tBuffer size: %zu\n", params[0].tmpref.size);
		params[0].tmpref.size = strlen(msg) + 1;
		memcpy(params[0].tmpref.buffer, msg, params[0].tmpref.size);
		printf("\tOK\n");
		break;
	case TA_OCALL_CA_CMD_TEST_6:
		printf("\tInput values: %u, %u\n", params[0].value.a,
			params[0].value.b);
		params[0].value.a = 0x3;
		params[0].value.b = 0x4;
		printf("\tOK\n");
		break;
	case TA_OCALL_CA_CMD_TEST_7:
		if (!params[0].tmpref.buffer) {
			printf("\tNo buffer\n");
			return TEEC_ERROR_BAD_PARAMETERS;
		}
		printf("\tInput string: %s\n", (char *)params[0].tmpref.buffer);
		printf("\tInput size: %zu\n", params[0].tmpref.size);
		params[0].tmpref.size = strlen(msg) + 1;
		memcpy(params[0].tmpref.buffer, msg,
			params[0].tmpref.size);
		printf("\tOK\n");
		break;
	case TA_OCALL_CA_CMD_TEST_8:
	case TA_OCALL_CA_CMD_TEST_9:
		if (!params[2].tmpref.buffer || !params[3].tmpref.buffer) {
			printf("\tNo buffer(s)\n");
			return TEEC_ERROR_BAD_PARAMETERS;
		}
		printf("\tInput values: %u, %u\n", params[0].value.a,
			params[0].value.b);

		printf("\tInout values: %u, %u\n", params[1].value.a,
			params[1].value.b);

		printf("\tInput string: %s\n", (char *)params[2].tmpref.buffer);
		printf("\tInput size: %zu\n", params[2].tmpref.size);

		printf("\tInout string: %s\n", (char *)params[3].tmpref.buffer);
		printf("\tInout size: %zu\n", params[3].tmpref.size);

		params[1].value.a = 0x3;
		params[1].value.b = 0x4;

		params[3].tmpref.size = strlen(msg) + 1;
		memcpy(params[3].tmpref.buffer, msg,
			params[3].tmpref.size);
		printf("\tOK\n");
		break;
	default:
		printf("\tBad function ID!\n");
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	return TEEC_SUCCESS;
}

static void run_test_no_ecall_params(uint32_t cmd_id)
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_OCALL_UUID;
	TEEC_Operation op = { 0 };

	TEEC_Result res;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	TEEC_SessionSettingOcall ocall_setting = { ocall_handler, &sess };
	TEEC_SessionSetting settings[] = {
		{ .type = TEEC_SESSION_SETTING_OCALL,
		  .u.ocall = &ocall_setting }
	};
	res = TEEC_OpenSessionEx(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
				 NULL, &err_origin, settings, 1);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSessionEx failed with code 0x%x origin 0x%x",
			res, err_origin);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_NONE,
		TEEC_NONE,
		TEEC_NONE,
		TEEC_NONE);

	printf("ECALL: %u\n", cmd_id);
	res = TEEC_InvokeCommand(&sess, cmd_id, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);
}

static void run_test_ecall_params_1()
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_OCALL_UUID;
	TEEC_Operation op = { 0 };

	TEEC_Result res;
	uint32_t err_origin;

 	char buf[128];
	char *msg1 = "This string was sent by the CA";
	const char *msg2 = "The CA thinks this is a fun riddle";

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	TEEC_SessionSettingOcall ocall_setting = { ocall_handler, &sess };
	TEEC_SessionSetting settings[] = {
		{ .type = TEEC_SESSION_SETTING_OCALL,
		  .u.ocall = &ocall_setting }
	};
	res = TEEC_OpenSessionEx(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
				 NULL, &err_origin, settings, 1);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSessionEx failed with code 0x%x origin 0x%x",
			res, err_origin);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT,
		TEEC_VALUE_INOUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INOUT);

	op.params[0].value.a = 0x3;
	op.params[0].value.b = 0x4;

	op.params[1].value.a = 0x5;
	op.params[1].value.b = 0x6;

	op.params[2].tmpref.buffer = msg1;
	op.params[2].tmpref.size = strlen(msg1) + 1;

	op.params[3].tmpref.buffer = buf;
	op.params[3].tmpref.size = sizeof(buf);
	memcpy(buf, msg2, strlen(msg2) + 1);

	printf("ECALL: %u\n", TA_OCALL_CMD_TEST_9);
	res = TEEC_InvokeCommand(&sess, TA_OCALL_CMD_TEST_9, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	printf("\tInout values: %u, %u\n", op.params[1].value.a,
				op.params[1].value.b);

	printf("\tInout string: %s\n", (char *)op.params[3].tmpref.buffer);
	printf("\tInout size: %zu\n", op.params[3].tmpref.size);

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);
}

int main(int argc, char* argv[])
{
	uint32_t cmd_id;

	for (cmd_id = TA_OCALL_CMD_TEST_1;
	     cmd_id <= TA_OCALL_CMD_TEST_8;
	     cmd_id++)
	     run_test_no_ecall_params(cmd_id);

	run_test_ecall_params_1();

	return 0;
}
