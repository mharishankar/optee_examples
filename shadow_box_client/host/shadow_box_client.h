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

#ifndef TA_SHADOW_BOX_H
#define TA_SHADOW_BOX_H

//=============================================================================
// Macros
//=============================================================================
/* This UUID is generated with uuidgen
   the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html */
#define TA_SHADOW_BOX_UUID { 0x8aaaf200, 0x2450, 0x11e4, \
		{ 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b} }

#define HASH_DUMP_HEADER_MAGIC 			"== SHADOW-BOX HASH DUMP FILE =="
#define REMOTE_ATTESTAION_HEADER_MAGIC 	"== SHADOW-BOX RA DATA =="

/* The Trusted Application Function ID(s) implemented in this TA */
#define SHA1_HASH_SIZE					20
#define SHA256_HASH_SIZE				32	

#define TA_HELLO_WORLD_CMD_INC_VALUE	0

#define VERIFY_RESULT_PROCESSING		0
#define VERIFY_RESULT_SUCCESS			1
#define VERIFY_RESULT_FAIL				2

#define TA_CMD_REQUEST_SHA1_HASH		0
#define TA_CMD_REQUEST_SHA256_HASH		1
#define TA_CMD_SEND_HASH_TABLE			2
#define TA_CMD_REQUEST_PROTECTION		3
#define TA_CMD_GET_STATUS				4

#define SERVER_PORT						8885
#define ADDRESS_TABLE_MAX_COUNT			100

//=============================================================================
// Structures
//=============================================================================
// Request sturecture for generating kernel hashes from normal world
struct request_hash
{
	unsigned long addr;		// physical addr
	unsigned long size;		// size
};

// Object structure of the hash dump file
struct sha1_hash_item
{
	unsigned long addr;
	unsigned long size;
	unsigned char hash[SHA1_HASH_SIZE];
};

// File header of the hash dump file
struct hash_dump_file_header
{
	char magic[32];
	unsigned int version;					// Dump file version
	unsigned long hash_count;				// Item count
	//struct sha1_hash_item* hash_table;	// Start point of sha1_hash_item
};

// Remote attestation server에서 서버로 요청
// Python과 통신할 용도이므로 packed를 사용해서 패딩을 모두 없앰
// Shadow-box의 상태 정보를 저장하는 구조체
struct shadow_box_status
{
	char magic[24]; 
	unsigned int nonce;						// Received nonce
	int verify_result;						// VERIFY_RESULT_SUCCESS or VERIFY_RESULT_SUCCESS
	unsigned long time_success;				// Success time
	unsigned long time_fail;				// Fail time
	//char dummy[0];						// Pad for 32byte align
} __attribute__((packed));

// Remote attestation server 에서 수신된 데이터
struct request_remote_attestation
{
	char magic[24]; 
	unsigned int nonce;						// Nonce
	unsigned int pad;						// Pad for SHA1
} __attribute__((packed));


#endif /*TA_SHADOW_BOX_H*/
