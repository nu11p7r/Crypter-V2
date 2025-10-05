#include "Crypto.h"

int main()
{
	while (true)
	{
		printf("select options\n1. Encrypt\t2. Decrypt\t4. Close\nInput: ");
		int nOption = -1;
		scanf("%d", &nOption);
		ClearInputBuffer();

		printf("you selected option: %d\n", nOption);

		if (nOption == 4)
		{
			break;
		}

		char szFileName[256] = { 0 };
		printf("Enter your file name: ");
		scanf("%s", szFileName);
		ClearInputBuffer();

		char szFinalFileName[260] = { 0 };
		char szTempFileName[260] = { 0 };

		printf("Starting...\n");

		CCrypto hCrypto;
		bool bSuccess = false;

		if (nOption == 1)
		{
			sprintf(szFinalFileName, "%s.n0nx0r", szFileName);
			sprintf(szTempFileName, "%s.tmp", szFinalFileName);

			FILE *pFileCheck = fopen("key.txt", "rb");
			if (pFileCheck == NULL)
			{
				pFileCheck = fopen("iv.txt", "rb");
			}

			if (pFileCheck != NULL)
			{
				fclose(pFileCheck);
				printf("\nWarning: key.txt and/or iv.txt already exist.\n");
				printf("Do you want to overwrite them? (y/n): ");

				char cResponse = 0;
				scanf(" %c", &cResponse);
				ClearInputBuffer();

				if (cResponse != 'y' && cResponse != 'Y')
				{
					printf("Operation cancelled by user.\n");
					continue; // while 루프 계속
				}
			}

			hCrypto.InitializationIV();

			printf("Encrypting '%s'...\n", szFileName);
			bSuccess = EncryptLargeFileWithCrypto(hCrypto, szFileName, szTempFileName);

			if (bSuccess)
			{
				FILE *pFileKey = fopen("key.txt", "wb");
				if (pFileKey)
				{
					fwrite(hCrypto.GetKey(), 1, AES_KEY_SIZE, pFileKey);
					fclose(pFileKey);
				}
				FILE *pFileIv = fopen("iv.txt", "wb");
				if (pFileIv)
				{
					fwrite(hCrypto.GetIV(), 1, AES_BLOCK_SIZE, pFileIv);
					fclose(pFileIv);
				}
			}
		}
		else if (nOption == 2)
		{
			strcpy(szFinalFileName, szFileName);
			char *pszExt = strstr(szFinalFileName, ".n0nx0r");

			// 확장자 바꾸면 길이 수정하셈
			if (pszExt != NULL && strlen(pszExt) == 7)
			{
				*pszExt = '\0';
			}
			else
			{
				printf("Warning: File does not have a .n0nx0r extension. Decrypting to '%s.dec'.\n", szFileName);
				sprintf(szFinalFileName, "%s.dec", szFileName);
			}
			sprintf(szTempFileName, "%s.tmp", szFinalFileName);

			byte byKey[AES_KEY_SIZE] = { 0 };
			byte byIv[AES_BLOCK_SIZE] = { 0 };

			FILE *pFileKey = fopen("key.txt", "rb");
			if (!pFileKey)
			{
				printf("Error: key.txt not found.\n");
				continue;
			}
			fread(byKey, 1, AES_KEY_SIZE, pFileKey);
			fclose(pFileKey);

			FILE *pFileIv = fopen("iv.txt", "rb");
			if (!pFileIv)
			{
				printf("Error: iv.txt not found.\n");
				continue;
			}
			fread(byIv, 1, AES_BLOCK_SIZE, pFileIv);
			fclose(pFileIv);

			hCrypto.CopyKey(byKey);
			hCrypto.CopyIV(byIv);

			printf("Decrypting '%s'...\n", szFileName);
			bSuccess = DecryptLargeFileWithCrypto(hCrypto, szFileName, szTempFileName);
		}
		else
		{
			printf("Invalid option.\n");
			continue;
		}

		if (bSuccess)
		{
			printf("\nProcessing successful. Finalizing files...\n");
			if (remove(szFileName) != 0)
			{
				perror("Error deleting original file");
			}
			else if (rename(szTempFileName, szFinalFileName) != 0)
			{
				perror("Error renaming temporary file");
			}
			else
			{
				printf("File '%s' has been successfully created.\n", szFinalFileName);
			}
		}
		else
		{
			printf("\nProcessing failed. Cleaning up temporary file...\n");
			remove(szTempFileName);
		}

		printf("Finish!!!\n\n");
	}

	return 0;
}