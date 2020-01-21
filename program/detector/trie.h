#ifndef trie_h
#define trie_h

typedef struct{
	struct node* child[set_size];
	bool is_leaf
} node;

typedef struct{
	node* root;
} trie;

trie* create_trie();

node* add_node();

void insert(trie* trie, char* str);

bool search(trie* trie, char* str);

bool deletion(trie* trie, char* str);

bool have_children(node* current);

#endif
