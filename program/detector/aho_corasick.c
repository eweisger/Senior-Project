#include <string.h>
#include <stdlib.h>

const int MaxStates = 6 * 50 + 10;
const int MaxChars = 26;

int Out[MaxStates];
int FF[MaxStates];
int GF[MaxStates][MaxChars];

int* AddItemInArray(int* arr, int count, int item) {
		int* newArr = (int*)malloc(sizeof(int) * (count + 1));

			for (int i = 0; i < count; ++i) {
						newArr[i] = arr[i];
							}

				newArr[count] = item;

					return newArr;
}

int* InsertItemInArray(int* arr, int count, int index, int item) {
		int* newArr = (int*)malloc(sizeof(int) * (count + 1));

			for (int i = 0; i < index; ++i) {
						newArr[i] = arr[i];
							}

				newArr[index] = item;

					for (int i = index; i < count; ++i) {
								newArr[i + 1] = arr[i];
									}

						return newArr;
}

int* RemoveItemFromArray(int* arr, int count, int index) {
		int* newArr = (int*)malloc(sizeof(int) * (count - 1));

			for (int i = 0; i < index; ++i) {
						newArr[i] = arr[i];
							}

				for (int i = index + 1; i < count; ++i) {
							newArr[i - 1] = arr[i];
								}

					return newArr;
}

int BuildMatchingMachine(const char** words, int wordsCount, char lowestChar = 'a', char highestChar = 'z')
{
		memset(Out, 0, sizeof Out);
			memset(FF, -1, sizeof FF);
				memset(GF, -1, sizeof GF);

					int states = 1;

						for (int i = 0; i < wordsCount; ++i)
								{
											const char* keyword = words[i];
													int currentState = 0;

															for (int j = 0; j < strlen(keyword); ++j)
																		{
																						int c = keyword[j] - lowestChar;

																									if (GF[currentState][c] == -1)
																													{
																																		GF[currentState][c] = states++;
																																					}

																												currentState = GF[currentState][c];
																														}

																	Out[currentState] |= (1 << i);
																		}

							for (int c = 0; c < MaxChars; ++c)
									{
												if (GF[0][c] == -1)
															{
																			GF[0][c] = 0;
																					}
													}

								int* q = (int*)malloc(sizeof(int));
									int qSize = 0;
										for (int c = 0; c <= highestChar - lowestChar; ++c)
												{
															if (GF[0][c] != -1 && GF[0][c] != 0)
																		{
																						FF[GF[0][c]] = 0;
																									q = AddItemInArray(q, qSize++, GF[0][c]);
																											}
																}

											while (qSize)
													{
																int state = q[0];
																		q = RemoveItemFromArray(q, qSize--, 0);

																				for (int c = 0; c <= highestChar - lowestChar; ++c)
																							{
																											if (GF[state][c] != -1)
																															{
																																				int failure = FF[state];

																																								while (GF[failure][c] == -1)
																																													{
																																																			failure = FF[failure];
																																																							}

																																												failure = GF[failure][c];
																																																FF[GF[state][c]] = failure;
																																																				Out[GF[state][c]] |= Out[failure];
																																																								q = AddItemInArray(q, qSize++, GF[state][c]);
																																																											}
																													}
																					}

												return states;
}

int FindNextState(int currentState, char nextInput, char lowestChar = 'a')
{
		int answer = currentState;
			int c = nextInput - lowestChar;

				while (GF[answer][c] == -1)
						{
									answer = FF[answer];
										}

					return GF[answer][c];
}

int* FindAllStates(const char* text, const char** keywords, int keywordsCount, char lowestChar = 'a', char highestChar = 'z') {
		BuildMatchingMachine(keywords, keywordsCount, lowestChar, highestChar);

			int currentState = 0;
				int* retVal = (int*)malloc(sizeof(int));;
					int retValSize = 0;

						for (int i = 0; i < strlen(text); ++i)
								{
											currentState = FindNextState(currentState, text[i], lowestChar);

													if (Out[currentState] == 0)
																	continue;

															for (int j = 0; j < keywordsCount; ++j)
																		{
																						if (Out[currentState] & (1 << j))
																										{
																															retVal = InsertItemInArray(retVal, retValSize++, 0, i - strlen(keywords[j]) + 1);
																																		}
																								}
																}

							return retVal;
}
