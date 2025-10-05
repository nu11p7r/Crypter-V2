#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <vector>
#include <iostream>
#include "../Common/Common.hpp"
#include "Security.hpp"

#define CHUNK_SIZE     (1024 * 1024 * 16) // 16MB
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE   32

#define SIGNATURE		"테스트 시그니처"
#define SIGNATURE_SIZE	sizeof(SIGNATURE)

using namespace Security;

void ClearInputBuffer();
bool EncryptLargeFileWithCrypto(CCrypto &hCrypto, const char *pszInputFile, const char *pszOutputFile);
bool DecryptLargeFileWithCrypto(CCrypto &hCrypto, const char *pszInputFile, const char *pszOutputFile);
void PrintProgress(int nPercent);


