#ifndef aho_corasick_h
#define aho_corasick_h

int* AddItemInArray(int* arr, int count, int item);

int* InsertItemInArray(int* arr, int count, int index, int item);

int* RemoveItemFromArray(int* arr, int count, int index);

int BuildMatchingMachine(const char** words, int wordsCount, char lowestChar = 'a', char highestChar = 'z');

int FindNextState(int currentState, char nextInput, char lowestChar = 'a');

int* FindAllStates(const char* text, const char** keywords, int keywordsCount, char lowestChar = 'a', char highestChar = 'z');

#endif
