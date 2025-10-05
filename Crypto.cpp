#define _CRT_SECURE_NO_WARNINGS
#include "Crypto.h"

void PrintProgress(int nPercent)
{
	const int cnBarWidth = 50;
	int nPos = cnBarWidth * nPercent / 100;

	printf("\rProgress: [");
	for (int nIndex = 0; nIndex < cnBarWidth; ++nIndex)
	{
		if (nIndex < nPos)
		{
			printf("=");
		}
		else if (nIndex == nPos)
		{
			printf(">");
		}
		else
		{
			printf(" ");
		}
	}
	printf("] %3d%%", nPercent);
	fflush(stdout);
}

bool EncryptLargeFileWithCrypto(CCrypto &hCrypto, const char *pszInputFile, const char *pszOutputFile)
{
	FILE *pInFile = fopen(pszInputFile, "rb");
	if (!pInFile)
	{
		printf("Error opening input file.\n");
		return false;
	}

	_fseeki64(pInFile, 0, SEEK_END);
	long long llTotalSize = _ftelli64(pInFile);
	_fseeki64(pInFile, 0, SEEK_SET);

	FILE *pOutFile = fopen(pszOutputFile, "wb");
	if (!pOutFile)
	{
		printf("Error opening output file.\n");
		fclose(pInFile);
		return false;
	}

	byte bySignatureBuffer[SIGNATURE_SIZE] = { 0 };
	strcpy((char *)bySignatureBuffer, SIGNATURE);
	fwrite(bySignatureBuffer, 1, SIGNATURE_SIZE, pOutFile);

	std::vector<byte> vecInBuffer(CHUNK_SIZE);
	byte byCurrentIv[AES_BLOCK_SIZE];
	memcpy(byCurrentIv, hCrypto.GetIV(), AES_BLOCK_SIZE);

	bool bStatus = true;
	size_t stBytesRead;

	long long llProcessedSize = 0;
	int nLastPercent = -1;
	PrintProgress(0);

	while ((stBytesRead = fread(vecInBuffer.data(), 1, CHUNK_SIZE, pInFile)) > 0)
	{
		byte *pbResult = hCrypto.Padding(vecInBuffer.data(), stBytesRead);
		byte *pbEncryptedData = hCrypto.CAES::EncryptCBC(pbResult, stBytesRead, hCrypto.GetKey(), byCurrentIv);
		if (pbEncryptedData == nullptr)
		{
			bStatus = false;
			delete[] pbResult; // 메모리 누수 방지
			break;
		}
		fwrite(pbEncryptedData, 1, stBytesRead, pOutFile);

		if (stBytesRead >= AES_BLOCK_SIZE)
		{
			memcpy(byCurrentIv, pbEncryptedData + stBytesRead - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		}
		delete[] pbResult;
		delete[] pbEncryptedData;

		llProcessedSize += stBytesRead;
		// llTotalSize가 0일 경우 나누기 오류 방지
		if (llTotalSize > 0)
		{
			int nPercent = (int)(100.0 * llProcessedSize / llTotalSize);
			if (nPercent > nLastPercent)
			{
				PrintProgress(nPercent);
				nLastPercent = nPercent;
			}
		}
	}

	if (bStatus)
	{
		PrintProgress(100);
	}
	printf("\n");

	fclose(pInFile);
	fclose(pOutFile);
	return bStatus;
}

bool DecryptLargeFileWithCrypto(CCrypto &hCrypto, const char *pszInputFile, const char *pszOutputFile)
{
	FILE *pInFile = fopen(pszInputFile, "rb");
	if (!pInFile)
	{
		printf("Error opening input file.\n");
		return false;
	}

	_fseeki64(pInFile, 0, SEEK_END);
	long long llTotalSize = _ftelli64(pInFile);
	_fseeki64(pInFile, 0, SEEK_SET);

	FILE *pOutFile = fopen(pszOutputFile, "wb");
	if (!pOutFile)
	{
		printf("Error opening output file.\n");
		fclose(pInFile);
		return false;
	}

	byte byReadSignature[SIGNATURE_SIZE] = { 0 };
	if (fread(byReadSignature, 1, SIGNATURE_SIZE, pInFile) != SIGNATURE_SIZE)
	{
		printf("\nError: File is too small to be a valid encrypted file.\n");
		fclose(pInFile);
		fclose(pOutFile);
		return false;
	}

	byte byExpectedSignature[SIGNATURE_SIZE] = { 0 };
	strcpy((char *)byExpectedSignature, SIGNATURE);

	if (memcmp(byReadSignature, byExpectedSignature, SIGNATURE_SIZE) != 0)
	{
		printf("\nError: Not a valid encrypted file or the format is incorrect.\n");
		fclose(pInFile);
		fclose(pOutFile);
		return false;
	}

	std::vector<byte> vecInBuffer(CHUNK_SIZE);
	byte byCurrentIv[AES_BLOCK_SIZE];
	memcpy(byCurrentIv, hCrypto.GetIV(), AES_BLOCK_SIZE);

	std::vector<byte> vecPrevCiphertextChunk(AES_BLOCK_SIZE);
	bool bStatus = true;
	size_t stBytesRead;

	long long llDataSize = llTotalSize - SIGNATURE_SIZE;
	long long llProcessedSize = 0;
	int nLastPercent = -1;
	PrintProgress(0);

	while ((stBytesRead = fread(vecInBuffer.data(), 1, CHUNK_SIZE, pInFile)) > 0)
	{
		if (stBytesRead >= AES_BLOCK_SIZE)
		{
			memcpy(vecPrevCiphertextChunk.data(), vecInBuffer.data() + stBytesRead - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		}

		byte *pbDecryptedData = hCrypto.CAES::DecryptCBC(vecInBuffer.data(), stBytesRead, hCrypto.GetKey(), byCurrentIv);
		// DecryptCBC 실패 시 nullptr
		if (pbDecryptedData == nullptr)
		{
			bStatus = false;
			break;
		}

		byte *pbResultData = hCrypto.UnPadding(pbDecryptedData, stBytesRead);
		if (pbResultData == nullptr)
		{
			bStatus = false;
			delete[] pbDecryptedData; // 메모리 누수 방지
			break;
		}
		fwrite(pbResultData, 1, stBytesRead, pOutFile);

		memcpy(byCurrentIv, vecPrevCiphertextChunk.data(), AES_BLOCK_SIZE);
		delete[] pbDecryptedData;
		delete[] pbResultData;
		llProcessedSize += stBytesRead;

		if (llDataSize > 0)
		{
			int nPercent = (int)(100.0 * llProcessedSize / llDataSize);
			if (nPercent > nLastPercent)
			{
				PrintProgress(nPercent);
				nLastPercent = nPercent;
			}
		}
	}

	if (bStatus)
	{
		PrintProgress(100);
	}
	printf("\n");

	fclose(pInFile);
	fclose(pOutFile);
	return bStatus;
}

void ClearInputBuffer()
{
	int nChar;
	while ((nChar = getchar()) != '\n' && nChar != EOF);
}