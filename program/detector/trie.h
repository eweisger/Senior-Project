#ifndef trie_h
#define trie_h

#define set_size 4
#define pmv_size 16

typedef struct{
	struct node* child[set_size];
	struct node* suffix_link;
	struct node* output_link;
	bool is_leaf;
} node;

typedef struct{
	node* root;
} trie;

trie* create_trie();

node* add_node();

void insert(trie* trie, char* str);

bool search(trie* trie, char* str);

#endif
