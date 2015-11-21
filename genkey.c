#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "common.h"

/* Usage: genkey FILENAME
 * Generate a key and write it to the file FILENAME. */

/* Interpret the 256 bits in buf as a private key and return an EC_KEY *. */
static EC_KEY *generate_key_from_buffer(const unsigned char buf[32])
{
	EC_KEY *key;
	BIGNUM *bn;
	int rc;

	key = NULL;
	bn = NULL;

	key = EC_KEY_new_by_curve_name(EC_GROUP_NID);
	if (key == NULL)
		goto err;

	bn = BN_bin2bn(buf, 32, NULL);
	if (bn == NULL)
		goto err;

	rc = EC_KEY_set_private_key(key, bn);
	if (rc != 1)
		goto err;

	BN_free(bn);

	return key;

err:
	if (key != NULL)
		EC_KEY_free(key);
	if (bn != NULL)
		BN_free(bn);
	return NULL;
}

static EC_KEY *generate_weak_key(void){
	unsigned char buf[32];
	int i;
	srand(1234);
	for (i = 0; i < 32; i++) {
		buf[i] = rand() & 0xff;
	}
	return generate_key_from_buffer(buf);	
}

EC_KEY *generate_key_on_time(time_t *t){
	unsigned char buf[32];
	int i;
	
	srand(*t);
	for (i = 0; i < 32; i++) {
		buf[i] = rand() & 0xff;
	}

	return generate_key_from_buffer(buf);
}


/* manually find out that generate time is UTC Oct 1 12:07:52*/ 
EC_KEY *generate_key_block_5(void){
	

	struct tm start = {.tm_year=2015-1900, .tm_mon=9, .tm_mday=1, .tm_hour=4, .tm_min=7, .tm_sec=52};
	time_t start_time = mktime(&start);
	struct tm *utc_start = gmtime(&start_time);
	printf("utc time %s\n", asctime(utc_start));
	EC_KEY *test_key;
	test_key = generate_key_on_time(&start_time);

	return test_key;
}





/* Generate a key using EC_KEY_generate_key. */
static EC_KEY *generate_key(void)
{
	EC_KEY *key;
	int rc;

	key = EC_KEY_new_by_curve_name(EC_GROUP_NID);
	if (key == NULL)
		return NULL;
	rc = EC_KEY_generate_key(key);
	if (rc != 1) {
		EC_KEY_free(key);
		return NULL;
	}

	return key;
}

int main(int argc, char *argv[])
{
	const char *filename;
	EC_KEY *key;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "need an output filename\n");
		exit(1);
	}

	filename = argv[1];

	// key = generate_key();

	key = generate_key_block_5();



	if (key == NULL) {
		fprintf(stderr, "error generating key\n");
		exit(1);
	}

	rc = key_write_filename(filename, key);
	if (rc != 1) {
		fprintf(stderr, "error saving key\n");
		exit(1);
	}

	EC_KEY_free(key);

	return 0;
}
