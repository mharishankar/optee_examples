#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>
#include <tee_client_api_extensions.h>

#include <ocall_ta.h>

TEEC_Result ocall_handler(void *context, TEEC_UUID *taUUID, uint32_t commandId,
						  uint32_t paramTypes,
						  TEEC_Parameter params[TEEC_CONFIG_PAYLOAD_REF_COUNT])
{
	printf("Have OCALL: %u\n", commandId);
	printf("The caller is: %x-%x-%x-%x%x-%x%x%x%x%x%x\n",
		taUUID->timeLow,
		taUUID->timeMid,
		taUUID->timeHiAndVersion,
		taUUID->clockSeqAndNode[0],
		taUUID->clockSeqAndNode[1],
		taUUID->clockSeqAndNode[2],
		taUUID->clockSeqAndNode[3],
		taUUID->clockSeqAndNode[4],
		taUUID->clockSeqAndNode[5],
		taUUID->clockSeqAndNode[6],
		taUUID->clockSeqAndNode[7]);

	return TEEC_SUCCESS;
}

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_OCALL_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,
						   &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res,
			 err_origin);

	res = TEEC_SetSessionOcallHandler(&sess, ocall_handler, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_SetSessionOcallHandler failed with code 0x%x", res,
			 err_origin);

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
									 TEEC_NONE);

	printf("Invoking TA\n");
	res = TEEC_InvokeCommand(&sess, TA_OCALL_CMD_TEST, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res,
			 err_origin);
	printf("TA invoked\n");

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
