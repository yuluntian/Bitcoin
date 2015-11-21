#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/ec.h>

#include "block.h"
#include "common.h"
#include "transaction.h"

#include "time.h"

/* Usage: ./balances *.blk
 * Reads in a list of block files and outputs a table of public key hashes and
 * their balance in the longest chain of blocks. In case there is more than one
 * chain of the longest length, chooses one arbitrarily. */

/* If a block has height 0, it must have this specific hash. */
const hash_output GENESIS_BLOCK_HASH = {
	0x00, 0x00, 0x00, 0x0e, 0x5a, 0xc9, 0x8c, 0x78, 0x98, 0x00, 0x70, 0x2a, 0xd2, 0xa6, 0xf3, 0xca,
	0x51, 0x0d, 0x40, 0x9d, 0x6c, 0xca, 0x89, 0x2e, 0xd1, 0xc7, 0x51, 0x98, 0xe0, 0x4b, 0xde, 0xec,
};



typedef struct blockchain_node {
	struct blockchain_node *parent;
	struct block b;
	int is_valid;
	hash_output myHash;
} blockchain_node;

static const struct blockchain_node EmptyNode;



/* A simple linked list to keep track of account balances. */
struct balance {
	struct ecdsa_pubkey pubkey;
	int balance;
	struct balance *next;
};

/* Add or subtract an amount from a linked list of balances. Call it like this:
 *   struct balance *balances = NULL;
 *
 *   // reward_tx increment.
 *   balances = balance_add(balances, &b.reward_tx.dest_pubkey, 1);
 *
 *   // normal_tx increment and decrement.
 *   balances = balance_add(balances, &b.normal_tx.dest_pubkey, 1);
 *   balances = balance_add(balances, &prev_transaction.dest_pubkey, -1);
 */


static struct balance *balance_add(struct balance *balances,
	struct ecdsa_pubkey *pubkey, int amount)
{
	struct balance *p;

	for (p = balances; p != NULL; p = p->next) {
		if ((byte32_cmp(p->pubkey.x, pubkey->x) == 0)
			&& (byte32_cmp(p->pubkey.y, pubkey->y) == 0)) {
			p->balance += amount;
			return balances;
		}
	}

	/* Not found; create a new list element. */
	p = malloc(sizeof(struct balance));
	if (p == NULL)
		return NULL;
	p->pubkey = *pubkey;
	p->balance = amount;
	p->next = balances;

	return p;

}

/*return 1 if the transaction referenced by normal_tx.prev_transaction_hash exists and the signature is valid, 0 otherwise*/
int check_prev_transaction(struct blockchain_node *p){

	struct transaction normal_tx = p->b.normal_tx;
	struct blockchain_node ancestor;
	struct blockchain_node *a = p->parent;
	hash_output reward_hash;
	hash_output normal_hash;
	while(a != NULL){
		if(a->is_valid == 0){
			a = a->parent;
			continue;
		}
		ancestor = *a;
		struct transaction r = ancestor.b.reward_tx;
		struct transaction n = ancestor.b.normal_tx;
		transaction_hash(&r, reward_hash);
		transaction_hash(&n, normal_hash);
		if(byte32_cmp(reward_hash, normal_tx.prev_transaction_hash) == 0){
			if(transaction_verify(&normal_tx, &r) == 1){
				return 1;
			}
		}
		if(byte32_cmp(normal_hash, normal_tx.prev_transaction_hash) == 0){
			if(transaction_verify(&normal_tx, &n) == 1){
				return 1;
			}
		}
		a = a->parent;
	}
	return 0;
}

/*return 1 if the transaction referenced by normal_tx.prev_transaction_hash has not been spent, 0 otherwise*/
int no_double_spending(struct blockchain_node *p){
	struct transaction normal_tx = p->b.normal_tx;
	struct blockchain_node ancestor;
	struct blockchain_node *a = p->parent;
	while(a != NULL){
		ancestor = *a;
		if(byte32_cmp(ancestor.b.normal_tx.prev_transaction_hash, normal_tx.prev_transaction_hash) == 0){
			return 0;
		}
		a = ancestor.parent;
	}
	return 1;
}




/* Find the previous transaction whose hash equals hash_output hash. Store its address in dest.*/
void find_prev_transaction_with_hash(struct blockchain_node *node, hash_output hash, struct transaction **dest){
	
	struct blockchain_node *curr = node->parent;
	
	while(curr != NULL){
		
		hash_output h;
		transaction_hash(&(curr->b.reward_tx), h);
		
		if(byte32_cmp(hash, h) == 0){
			*dest = &(curr->b.reward_tx);
			break;
		}


		if(byte32_is_zero(curr->b.normal_tx.prev_transaction_hash) == 0){
			transaction_hash(&(curr->b.normal_tx), h);
			
			if(byte32_cmp(hash, h) == 0){
				*dest = &(curr->b.normal_tx);
				break;
			}
		}
		curr = curr->parent;
	}
}




int main(int argc, char *argv[])
{
	int i;
	
	struct blockchain_node *blocks[argc - 1];
	struct blockchain_node *sorted_blocks[argc - 1];

	

	/* Read input block files. */
	for (i = 1; i < argc; i++) {
		char *filename;
		struct block b;
		int rc;

		filename = argv[i];
		rc = block_read_filename(&b, filename);
		if (rc != 1) {
			fprintf(stderr, "could not read %s\n", filename);
			exit(1);
		}


		blocks[i-1] = (blockchain_node *)malloc(sizeof(blockchain_node));		

		blocks[i-1]->parent = NULL;

		blocks[i-1]->b = b;

		blocks[i-1]->is_valid = 0;
		block_hash(&b, blocks[i-1]->myHash);
	}



	//sort
	
	uint32_t height;
	int index = 0;

	for(height = 0; height < argc - 1; height++){
		for (i = 0; i < argc - 1; i++){
			if(blocks[i]->b.height == height){
				sorted_blocks[index] = blocks[i];
				index = index + 1;
			}
		}
	}


	



	
	//generate tree
	int j;
	for(i = 0; i < argc-1; i++){
		for(j = 0; j < argc - 1; j++){
			if (byte32_cmp(sorted_blocks[j]->myHash, sorted_blocks[i]->b.prev_block_hash) == 0){

				sorted_blocks[i]->parent = sorted_blocks[j];
				break;
			}
		}
	}

	


	//validity check
	for(i = 0; i < argc-1; i++){
		
		
		struct blockchain_node node = *sorted_blocks[i];
		
		struct block bl = node.b;		

		struct block parent; 

		if (node.parent != NULL){

			
			parent = (node.parent)->b;

		}




		
					
		if(bl.height == 0 && byte32_cmp(node.myHash, GENESIS_BLOCK_HASH) != 0){
			node.is_valid = 0;
			continue;
		}



		if(bl.height != 0 && parent.height != bl.height - 1){
			node.is_valid = 0;
			continue;
		}


		if(hash_output_is_below_target(node.myHash) == 0){
			node.is_valid = 0;
			continue;
		}
		if(bl.reward_tx.height != bl.height || bl.normal_tx.height != bl.height){
			node.is_valid = 0;
			continue;
		}


		if(byte32_is_zero(bl.reward_tx.prev_transaction_hash) == 0 || byte32_is_zero(bl.reward_tx.src_signature.r) == 0 || byte32_is_zero(bl.reward_tx.src_signature.s) == 0){
			node.is_valid = 0;
			continue;
		}



		if(byte32_is_zero(bl.normal_tx.prev_transaction_hash) == 0){
			if(check_prev_transaction(&node) == 0){
				node.is_valid = 0;
				continue;
			}
			if(no_double_spending(&node) == 0){
				node.is_valid = 0;
				continue;
			}

		}
		
		sorted_blocks[i]->is_valid = 1;
	}


	// find longest chain
	struct blockchain_node *superNode = NULL;
	struct blockchain_node temp;
	int found = 0;
	for(i = argc-2; i >= 0; i--){
		temp = *sorted_blocks[i];
		while(temp.is_valid == 1){
			if(temp.parent == NULL){
				superNode = sorted_blocks[i];
				found = 1;
				break;
			}
			temp = *(temp.parent);
		}
		if(found == 1) break;
	}





	









	// compute balances
	struct balance *balances = NULL;
	struct blockchain_node *check_pointer = superNode;
	struct blockchain_node checkNode;
	struct transaction *prev_tx = NULL;
	while (check_pointer != NULL){
		checkNode = *check_pointer;
		struct block b = checkNode.b;

		balances = balance_add(balances, &b.reward_tx.dest_pubkey, 1);

		if (byte32_is_zero(b.normal_tx.prev_transaction_hash) == 0){
			balances = balance_add(balances, &b.normal_tx.dest_pubkey, 1);
			prev_tx = NULL;
			find_prev_transaction_with_hash(&checkNode, b.normal_tx.prev_transaction_hash, &prev_tx);
			if(prev_tx == NULL){
				printf("Error: previous transaction not found\n");
				exit(1);
			}
 			balances = balance_add(balances, &prev_tx->dest_pubkey, -1);
		}
		
		check_pointer = check_pointer -> parent;
		
	}
	struct balance *p, *next;
	for (p = balances; p != NULL; p = next) {
		next = p->next;
		printf("%s %d\n", byte32_to_hex(p->pubkey.x), p->balance);
		free(p);
	}

	for(i = 0; i < argc-1; i++){
		free(blocks[i]);
	}

	



















	








//##################################################################################################
//                                      CODE FOR PART 2                                           //
//##################################################################################################

	// printf("Find block 4 and 5\n");
	// struct block block4;
	// struct block block5;
	// struct blockchain_node *nn = superNode;
	// while(nn->b.height >= 4){
	// 	// printf("%d\n", nn->b.height);
	// 	if(nn->b.height == 5){
	// 		block5 = nn->b;
	// 	}
	// 	if(nn->b.height == 4){
	// 		block4 = nn->b;
	// 	}
	// 	nn = nn->parent;
	// }






	// printf("read my private key\n");
	// FILE *pp = NULL;
	// EC_KEY *mykey = NULL;
	// pp = fopen("mykey.priv", "rb");
	// if(pp == NULL){
	// 	printf("cannot read private key file\n");
	// 	exit(1);
	// }

	// mykey = key_read(pp);

	// if(mykey == NULL){
	// 	printf("cannot read my private key\n");
	// 	exit(1);
	// }
	// printf("done\n");






	// printf("read guessed key for block 4\n");
	// FILE *p4 = NULL;
	// EC_KEY *key4 = NULL;
	// p4 = fopen("1.pubkey", "rb");
	// if(p4 == NULL){
	// 	printf("cannot read guessed key file for block 4\n");
	// 	exit(1);
	// }
	// key4 = key_read(p4);
	// if (key4==NULL)
	// {
	// 	printf("cannot read guessed key for block 4\n");
	// }
	// fclose(p4);
	// printf("done\n");







	// // struct transaction reward;
	// // reward = block5.reward_tx;

	// // BIGNUM *x_check = BN_new();
	// // BIGNUM *y_check = BN_new();

	// // int x_length = BN_hex2bn(&x_check, byte32_to_hex(reward.dest_pubkey.x));
	// // int y_length = BN_hex2bn(&y_check, byte32_to_hex(reward.dest_pubkey.y));

	// // if(x_length == 0 || y_length == 0){
	// // 	printf("big number read error\n");
	// // 	exit(1);
	// // }

	// printf("read guessed key for block 5\n");
	// FILE *p5 = NULL;
	// EC_KEY *key5 = NULL;
	// p5 = fopen("2.pubkey", "rb");
	// if(p5 == NULL){
	// 	printf("cannot read guessed key file for block 5\n");
	// 	exit(1);
	// }
	// key5 = key_read(p5);
	// if (key5==NULL)
	// {
	// 	printf("cannot read guessed key for block 5\n");
	// }
	// fclose(p5);
	// printf("done\n");





	// printf("block 5 hash: %s\n", byte32_to_hex(superNode->myHash));
    


	// // BN_free(x_check);
	// // BN_free(y_check);
	// printf("done\n");





	


	// printf("superNode height: %d\n", superNode->b.height);







	// //create block 1

	// struct block bl1;
	// /* Build on top of the head of the main chain. */
	// block_init(&bl1, &superNode->b);

	// printf("myblock6 height: %d\n",bl1.height);
	// printf("block6 prev hash: %s\n", byte32_to_hex(bl1.prev_block_hash));
	// // hash_output h;
	// // block_hash(&superNode->b, h);
	// printf("block 5 hash: %s\n", byte32_to_hex(superNode->myHash));
	// /* Give the reward to us. */
	// transaction_set_dest_privkey(&bl1.reward_tx, mykey);
	// /* The last transaction was in block 4. */
	// transaction_set_prev_transaction(&bl1.normal_tx,
	// &block4.normal_tx);
	// /* Send it to us. */
	// transaction_set_dest_privkey(&bl1.normal_tx, mykey);
	// /* Sign it with the guessed private key. */
	// transaction_sign(&bl1.normal_tx, key4);
	// /* Mine the new block. */
	// printf("mining block 1\n");
	// block_mine(&bl1);
	// /* Save to a file. */
	// block_write_filename(&bl1, "myblock1.blk");
	// printf("done\n");


	// //create block 2
	// struct block bl2;
	// /* Build on top of the head of the main chain. */
	// block_init(&bl2, &bl1);
	// printf("myblock2 height: %d\n",bl2.height);
	// /* Give the reward to us. */
	// transaction_set_dest_privkey(&bl2.reward_tx, mykey);
	// /* The last transaction was in block 5. */
	// transaction_set_prev_transaction(&bl2.normal_tx,
	// &block5.reward_tx);
	// /* Send it to us. */
	// transaction_set_dest_privkey(&bl2.normal_tx, mykey);
	// /* Sign it with the guessed private key. */
	// transaction_sign(&bl2.normal_tx, key5);
	// /* Mine the new block. */
	// printf("mining block 2\n");
	// block_mine(&bl2);
	// /* Save to a file. */
	// block_write_filename(&bl2, "myblock2.blk");
	// printf("done\n");

	

	// EC_KEY_free(mykey);
	// EC_KEY_free(key4);
	// EC_KEY_free(key5);

	// for(i = 0; i < argc-1; i++){
	// 	free(blocks[i]);
	// }
	
	

	return 0;
}
