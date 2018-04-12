/*
 *                      Shadow-Box for ARM
 *                      ------------------
 *             ARM TrustZone-Based Kernel Protector
 *
 *               Copyright (C) 2018 Seunghun Han
 *     at National Security Research Institute of South Korea
 */

/*
 * This software has dual license (MIT and GPL v2). See the GPL_LICENSE and
 * MIT_LICENSE file.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <netinet/in.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include "shadow_box_client.h"

static void dump_hash(unsigned char *hash, unsigned long len)
{
	unsigned long i;

    for (i = 0; i < len; i++)
	{
		printf("%02x", hash[i]);
	}
}

/**
 * Write a file header of the hash dump file.
 */
static void write_hash_dump_header(int fd, unsigned long count)
{
	struct hash_dump_file_header header;

	strcpy(header.magic, HASH_DUMP_HEADER_MAGIC);
	header.version = 0;
	header.hash_count = count;

	write(fd, &header, sizeof(header));
}

/**
 * Write a SHA1 hash with address and size to the hash dump file.
 */
static void write_sha1_hash_dump(int fd, unsigned long addr, unsigned long size, unsigned char* hash)
{
	struct sha1_hash_item item;

	item.addr = addr;
	item.size = size;
	memcpy(item.hash, hash, sizeof(item.hash));

	write(fd, &item, sizeof(item));
}

/**
 * Read start and end address from the address table file.
 */
static int read_address_table(unsigned long start[ADDRESS_TABLE_MAX_COUNT], unsigned long end[ADDRESS_TABLE_MAX_COUNT], unsigned int* real_count)
{
	FILE* fp;
	unsigned int count;
	unsigned int i;

	fp = fopen("address_table.dat", "r");
	if (fp == NULL)
	{
		printf("addrss_table.dat open error\n");
		return -1;
	}
	
	if (fscanf(fp, "%u", &count) < 0)
	{
		return -1;
	}
	printf("    [*] count = %d\n", count);
	*real_count = count;

	if (count > ADDRESS_TABLE_MAX_COUNT)
	{
		count = ADDRESS_TABLE_MAX_COUNT;
	}

	for (i = 0 ; i < count ; i++)
	{
		if (fscanf(fp, "%lx", &(start[i])) < 0)
		{
			return -1;
		}

		if (fscanf(fp, "%lx", &(end[i])) < 0)
		{
			return -1;
		}
		printf("    [*] Start = %lX, End = %lX\n", start[i], end[i]);
	}

	return 0;
}

/**
 * Generate hash dump file.
 */
static void generate_hash_table(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SHADOW_BOX_UUID;
	uint32_t err_origin;
	unsigned long log_start[ADDRESS_TABLE_MAX_COUNT] = {0, };
	unsigned long log_end[ADDRESS_TABLE_MAX_COUNT] = {0, };
	unsigned char out_buffer[100] = {0, };
	unsigned char out_buffer2[100] = {0, };
	unsigned long i;
	unsigned int j;
	unsigned long loop;
	unsigned int address_count;
	unsigned long count;
#if SHADOW_BOX_USE_KERNEL_DRIVER
    int shadow_box_fd;
#endif
	int dump_fd;
	struct request_hash data;
	struct request_hash* pdata;

	if (read_address_table(log_start, log_end, &address_count) != 0)
	{
		return ;
	}

    dump_fd = open("hash_table.dat", O_WRONLY | O_CREAT, 0644);
#if SHADOW_BOX_USE_KERNEL_DRIVER
    shadow_box_fd = open("/dev/hello", O_RDONLY);
    if ((shadow_box_fd == -1) || (dump_fd == -1))
    {   
        printf("Kernel module or hash file open Error, %d %d\n", shadow_box_fd, dump_fd);
		return ;
    }   
#else
    if (dump_fd == -1)
    {   
        printf("Hash file open Error, %d\n", dump_fd);
		return ;
    }   
#endif
   else
    {   
        printf("Kernel module and hash file open Success\n");
    } 

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
	{
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
	}

	for (j = 0 ; j < address_count ; j++)
	{
		loop = 0;
		count = (log_end[j] - log_start[j]) / 0x1000;

		write_hash_dump_header(dump_fd, count);
		
		for (i = log_start[j] ; i < log_end[j] ; i += 0x1000)
		{
			memset(&op, 0, sizeof(op));
			
			loop++;
			printf("[%02ld%%, cur:%ld, end:%ld] %lX, Secure: ", (loop * 100 / count), loop, count, i);

			// Request a SHA1 hash of physical address.
			op.paramTypes = TEEC_PARAM_TYPES(
								TEEC_NONE,
								TEEC_MEMREF_TEMP_INPUT,
								TEEC_MEMREF_TEMP_OUTPUT, 
								TEEC_NONE);
			
			// Logical to physical convert
			data.addr = i & 0xFFFFFFFF;
			data.size = 0x1000;

			op.params[1].tmpref.buffer = (void*)&data;
			op.params[1].tmpref.size = sizeof(data);
			op.params[2].tmpref.buffer = (void*)out_buffer;
			op.params[2].tmpref.size = sizeof(out_buffer);

			res = TEEC_InvokeCommand(&sess, TA_CMD_REQUEST_SHA1_HASH, &op, &err_origin);
			if (res != TEEC_SUCCESS)
			{
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
			}

			dump_hash(out_buffer, SHA1_HASH_SIZE);
#if SHADOW_BOX_USE_KERNEL_DRIVER
			printf(", Normal: ");

			// Normal world 
			pdata = (struct request_hash*)out_buffer2;
			pdata->addr = i; 
			pdata->size = 0x1000;
			ioctl(shadow_box_fd, 0, pdata);
			
			dump_hash(out_buffer2, SHA1_HASH_SIZE);

			if (memcmp(out_buffer, out_buffer2, SHA1_HASH_SIZE) == 0)
			{
				printf(" same \n");
			}
			else
			{
				printf(" not same \n");
				return ;
			}
#else
			printf("\n");
#endif

			write_sha1_hash_dump(dump_fd, i & 0xFFFFFFFF, 0x1000, out_buffer);
		}
	}

	TEEC_CloseSession(&sess);
	
	TEEC_FinalizeContext(&ctx);

#if SHADOW_BOX_USE_KERNEL_DRIVER
    close(shadow_box_fd);
#endif

    close(dump_fd);
}

/**
 * Send hash dump file to Shadow-box trusted application (TA) of Secure world.
 */
static void send_hash_table_to_ta(char* filename)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SHADOW_BOX_UUID;
	uint32_t err_origin;
	int fd;
	unsigned long file_size;
	unsigned char *buffer = NULL;

    fd = open(filename, O_RDONLY);
    if (fd == -1)
    {   
        printf("%s file open error\n", filename);
		return ;
    }   
    else
    {   
        printf("%s file open success\n", filename);
    } 
	file_size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	printf("File size is %ld\n", file_size);

	buffer = malloc(file_size);
	if (buffer == NULL)
	{
		printf("Malloc fail\n");
		return ;
	}
	read(fd, buffer, file_size);

	// Send hash table to Shadow-box TA
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
	{
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
	}

	memset(&op, 0, sizeof(op));

	// Secure world
	op.paramTypes = TEEC_PARAM_TYPES(
						TEEC_NONE,
						TEEC_MEMREF_TEMP_INPUT,
						TEEC_MEMREF_TEMP_OUTPUT, 
						TEEC_NONE);
	
	op.params[1].tmpref.buffer = buffer;
	op.params[1].tmpref.size = file_size;
	op.params[2].tmpref.buffer = NULL;
	op.params[2].tmpref.size = 0;

	res = TEEC_InvokeCommand(&sess, TA_CMD_SEND_HASH_TABLE, &op, &err_origin);
	if (res != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
	}

	TEEC_CloseSession(&sess);
	
	TEEC_FinalizeContext(&ctx);

    close(fd);

	return ;
}

/**
 * Start kernel protection.
 */
static void start_protection(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SHADOW_BOX_UUID;
	uint32_t err_origin;
	long stat[4];
	long prev_stat[4];
	double average = 0;
	long interval;
	FILE* fp;
	int i;
	time_t last_time;

	// Send a command to Shadow-box TA
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
	{
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
	}

	fp = fopen("/proc/stat","r");
	fscanf(fp,"%*s %ld %ld %ld %ld",&prev_stat[0],&prev_stat[1],&prev_stat[2],&prev_stat[3]);
	fclose(fp);
	
	last_time = time(NULL);
	while(1)
	{
		memset(&op, 0, sizeof(op));

		// Secure world
		op.paramTypes = TEEC_PARAM_TYPES(
							TEEC_NONE,
							TEEC_MEMREF_TEMP_INPUT,
							TEEC_MEMREF_TEMP_OUTPUT, 
							TEEC_NONE);
		
		op.params[1].tmpref.buffer = NULL;
		op.params[1].tmpref.size = 0;
		op.params[2].tmpref.buffer = NULL;
		op.params[2].tmpref.size = 0;

		res = TEEC_InvokeCommand(&sess, TA_CMD_REQUEST_PROTECTION, &op, &err_origin);
		if (res != TEEC_SUCCESS)
		{
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		}

		// Change interval according to CPU load.
		if (average < 30)
		{
			// 5ms sleep.
			interval =  5000;
		}
		else if (average < 70)
		{
			// 500ms sleep.
			interval =  500000;
			printf("Cpu load is over 30%%, change timer %ld\n", interval);
		}
		else
		{
			// 2 sleep.
			interval = 2000000;
			printf("Cpu load is over 70%%, change timer %ld\n", interval);
		}
		
		usleep(interval);

		fp = fopen("/proc/stat","r");
		fscanf(fp,"%*s %ld %ld %ld %ld",&stat[0],&stat[1],&stat[2],&stat[3]);
		fclose(fp);

		// Calculate CPU load.
		if (time(NULL) - last_time > 1)
		{
			average = (double)(stat[0] + stat[1] + stat[2] - prev_stat[0] - prev_stat[1] - prev_stat[2]) * 100 / (stat[0] + stat[1] + stat[2] + stat[3] - prev_stat[0] - prev_stat[1] - prev_stat[2] - prev_stat[3]) ;
		
			for (i = 0 ; i < 4 ; i++)
			{
				prev_stat[i] = stat[i];
			}
			
			printf("Cpu load is %.02f%%\n", average);

			last_time = time(NULL);
		}
	}

	TEEC_CloseSession(&sess);
	
	TEEC_FinalizeContext(&ctx);

	return ;
}

/**
 * Dump status of Shadow-box and kernel.
 */
static void dump_status(struct shadow_box_status* data)
{
	time_t t;
	struct tm local_tm;

	printf("Shadow-box status\n");

	switch(data->verify_result)
	{
		case VERIFY_RESULT_SUCCESS:
			printf("    [*] Verify Success\n");
			break;

		case VERIFY_RESULT_FAIL:
			printf("	[*] Verify Fail\n");
			break;

		case VERIFY_RESULT_PROCESSING:
			printf("    [*] Verifing\n");
			break;
	}
	
	t = data->time_success;
	if (data->time_success != 0)
	{
		local_tm = *localtime(&t);

		printf("    [*] Last success time: %04d/%02d/%02d %02d:%02d:%02d\n", local_tm.tm_year + 1900, local_tm.tm_mon + 1, local_tm.tm_mday, local_tm.tm_hour, local_tm.tm_min, local_tm.tm_sec);
	}
	else
	{
		printf("    [*] Last success time is not set\n");
	}

	t = data->time_fail;
	if (data->time_fail != 0)
	{
		local_tm = *localtime(&t);

		printf("    [*] Last fail time: %04d/%02d/%02d %02d:%02d:%02d\n", local_tm.tm_year + 1900, local_tm.tm_mon + 1, local_tm.tm_mday, local_tm.tm_hour, local_tm.tm_min, local_tm.tm_sec);
	}
	else
	{
		printf("    [*] Last fail time is not set\n");
	}
}

/**
 * Request status to Shadow-box TA.
 */
static int request_shadow_box_status(struct request_remote_attestation* request, struct shadow_box_status* status)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SHADOW_BOX_UUID;
	uint32_t err_origin;

	// Send a request to TA
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
		return -1;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
	{
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
		return -1;
	}

	memset(&op, 0, sizeof(op));

	// Secure world
	op.paramTypes = TEEC_PARAM_TYPES(
						TEEC_NONE,
						TEEC_MEMREF_TEMP_INPUT,
						TEEC_MEMREF_TEMP_OUTPUT, 
						TEEC_NONE);
	
	op.params[1].tmpref.buffer = request;
	op.params[1].tmpref.size = sizeof(struct request_remote_attestation);
	op.params[2].tmpref.buffer = status;
	op.params[2].tmpref.size = sizeof(struct shadow_box_status);

	res = TEEC_InvokeCommand(&sess, TA_CMD_GET_STATUS, &op, &err_origin);
	if (res != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		return -1;
	}

	//dump_status(status);
	printf("Success\n");

	TEEC_CloseSession(&sess);
	
	TEEC_FinalizeContext(&ctx);

	return 0;
}

/**
 * Start server for receiving a remote attestation request.
 */
void start_server(void)
{	
	struct request_remote_attestation request;
	struct shadow_box_status status;
	int server_sock;
	int client_sock;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	int enable = 1;
	socklen_t len;
	int recved;
	int cur_recved;
	int sent;
	int cur_sent;

	server_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (server_sock == -1)
	{
		printf("Socket error\n");
		return ;
	}

	if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
		printf("Setsockopt error\n");
		return ;
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(SERVER_PORT);

	if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		printf("Socket bind error\n");
		return ;
	}
	
	if (listen(server_sock, 5) < 0)
	{
		printf("Socket listen error\n");
		return ;
	}

	printf("Server port %d start\n", SERVER_PORT);

	while (1)
	{
		printf("\nWait for incoming connections...\n");
		len = sizeof(client_addr);
		client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &len);
		if (client_sock < 0)
		{
			close(server_sock);
			return ;
		}

		printf("Client is connected...\n");
		recved = 0;
		while(recved < sizeof(struct request_remote_attestation))
		{
			cur_recved = recv(client_sock, (char*)&request + recved, sizeof(struct request_remote_attestation) - recved, 0);
			if (cur_recved <= 0)
			{
				break;
			}

			recved += cur_recved;
			if (recved == sizeof(struct request_remote_attestation))
			{
				break;
			}
		}

		// Request status to Shadow-box TA and send back to the remote attestation server.
		if (request_shadow_box_status(&request, &status) == 0)
		{
			sent = 0;
			while(sent < sizeof(struct shadow_box_status))
			{
				cur_sent = send(client_sock, (char*)&status + sent, sizeof(struct shadow_box_status) - sent, 0);
				if (cur_sent <= 0)
				{
					break;
				}

				sent += cur_sent;
				if (sent == sizeof(struct shadow_box_status))
				{
					break;
				}
			}
		}

		close(client_sock);
	}
}

/**
 * Main funciton.
 */
int main(int argc, char *argv[])
{
	struct shadow_box_status status;

	if (argc < 2)
	{
		printf("option> -g          : Generate hash to file from address_table.dat file\n"
			   "        -h filename : Send hash file to TA\n"
			   "        -s          : Start protection\n" 
			   "        -l          : Start server for the remote attestation\n");
		return -1;
	}

	if (strcmp("-g", argv[1]) == 0)
	{
		generate_hash_table();
	}
	else if (strcmp("-h", argv[1]) == 0)
	{
		send_hash_table_to_ta(argv[2]);
	}
	else if (strcmp("-s", argv[1]) == 0)
	{
		start_protection();
	}
	else if (strcmp("-l", argv[1]) == 0)
	{
		start_server();
	}

	return 0;
}


