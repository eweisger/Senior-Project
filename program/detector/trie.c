#include <stdio.h>
#include <stdlib.h>
#include "trie.h"

#define set_size 4

trie* create_trie(){
	trie* trie = (trie*)malloc(sizeof(trie));
	trie->root = NULL;

	return trie;
}

node* add_node(){
	node* node = (node*)malloc(sizeof(node));
	
	node->is_leaf = false;
	for(int i = 0; i < set_size; i++)
		node->child[i] = NULL;

	return node;
}

void insert(trie* trie, char* str){
	node* current = trie->root;
	length = strlen(str)

	for(i = 0; i < length; i++){
		if(current->child[str[i]] == NULL)
			current->child[str[i]] = add_node();

		current = current->child[str[i]]
	}

	current->is_leaf = true;
}

bool search(trie* trie, char* str){
	if(trie->root == NULL)
		return false;

	node* current = trie->root;
	length = strlen(str);

	for(i = 0; i < length; i++){
		current = current->child[str[i]]
		
		if(current == NULL)
			return false;
	}
	
	return true;
}
