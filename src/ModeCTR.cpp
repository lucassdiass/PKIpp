/*
 * CTR.cpp
 *
 *  Created on: 5 de jan de 2021
 *      Author: Lucas Dias
 */

#include "PKISymmetric.hpp"
#include <openssl/rand.h>
using namespace PKI::Symmetric;

void AesCTRMode::ConfigureKey(std::string newKey)
{
	unsigned char *key=nullptr;
	if(newKey.size() == EVP_CIPHER_key_length(EVP_aes_256_ctr())) {
		SecretKey=newKey;
	} else if (newKey.size()<EVP_CIPHER_key_length(EVP_aes_256_ctr()))
	{
		key=new (std::nothrow) unsigned char[EVP_CIPHER_key_length(EVP_aes_256_ctr())-newKey.size()]{};
		if(key!=nullptr && RAND_bytes(key, sizeof(unsigned char)*(EVP_CIPHER_key_length(EVP_aes_256_ctr())-newKey.size())))
		{
			for(int index=0;index<(EVP_CIPHER_key_length(EVP_aes_256_ctr())-newKey.size());index++)
			{
				SecretKey.push_back(key[index]);
			}
			delete []key;
			key=nullptr;
		} else {
			throw std::runtime_error{"It was not possible generate the key"};
		}
	}
	else {
		for(int index=0;index < EVP_CIPHER_key_length(EVP_aes_256_ctr());index++)
		{
			SecretKey.push_back(newKey[index]);
		}

	}
}
void AesCTRMode::ConfigureIV(std::string newIV)
{
	unsigned char *iv=nullptr;
	if(newIV.empty())
	{
		iv=new (std::nothrow) unsigned char[EVP_CIPHER_iv_length(EVP_aes_256_ctr())]{};
		if(iv!=nullptr && RAND_bytes(iv, sizeof(unsigned char)*EVP_CIPHER_iv_length(EVP_aes_256_ctr())))
		{
			CTR.clear();
			for(int index=0;index<EVP_CIPHER_iv_length(EVP_aes_256_ctr());index++)
			{
				CTR.push_back(iv[index]);
			}
			delete []iv;
			iv=nullptr;
		}
		else
		{
			throw std::runtime_error{"It was not possible generate the IV"};
		}
	}
	else
	{
		CTR=newIV;
		if(CTR.size()<EVP_CIPHER_iv_length(EVP_aes_256_ctr()))
		{
			iv=new (std::nothrow) unsigned char[EVP_CIPHER_iv_length(EVP_aes_256_ctr())-newIV.size()]{};
			if(iv!=nullptr && RAND_bytes(iv, sizeof(unsigned char)*(EVP_CIPHER_iv_length(EVP_aes_256_ctr())-newIV.size())))
			{
				for(int index=0;index<(EVP_CIPHER_iv_length(EVP_aes_256_ctr())-newIV.size());index++)
				{
					CTR.push_back(iv[index]);
				}
			}
			delete []iv;
			iv=nullptr;
		}
	}
}

std::string AesCTRMode::EncryptMessage(const std::string&plain)
{
	if(!plain.size())
	{
		throw std::runtime_error{"Plain text is empty"};
	}
	std::string encrypted{};
	int len=0,ciphertext_len=0;
	float len_aux=0;
	EVP_CIPHER_CTX *ctx=nullptr;
	unsigned char * encrypted_aux=nullptr;
	try
	{
		if((ctx = EVP_CIPHER_CTX_new())!=nullptr)
		{
			if(EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, ( unsigned char *)SecretKey.data(), (unsigned char*) CTR.data())>0)
			{
				len_aux=(float)plain.size()/(float)EVP_CIPHER_block_size(EVP_aes_256_ctr());
				len=len_aux;
				if(len_aux!=(float)len)
				{
					len=(len*EVP_CIPHER_block_size(EVP_aes_256_ctr()))  +    EVP_CIPHER_block_size(EVP_aes_256_ctr());
				}
				else
				{
					len=(len*EVP_CIPHER_block_size(EVP_aes_256_ctr()));
				}

				encrypted_aux=(unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*(len) );
				len=0;

				if(encrypted_aux!=nullptr &&
						EVP_EncryptUpdate(ctx, encrypted_aux, &len, (unsigned char*)plain.data(), plain.size())>0
				)
				{
					ciphertext_len=len;
					if(EVP_EncryptFinal_ex(ctx, encrypted_aux + ciphertext_len, &len)>0)
					{
						ciphertext_len+=len;

						for(int index=0;index<ciphertext_len;index++)
						{
							encrypted.push_back(*(encrypted_aux+index));
						}
					}
				}
				OPENSSL_free(encrypted_aux);
				encrypted_aux=nullptr;

			}
		}
		EVP_CIPHER_CTX_free(ctx);
	}
	catch(...)
	{
		throw;
	}
	if(!encrypted.size())
	{
		throw std::runtime_error{"It was not possible encrypt the message"};
	}
	return encrypted;
}
std::string AesCTRMode::DecryptMessage(const std::string& encrypted)
{
	if(!encrypted.size())
	{
		throw std::runtime_error{"Encrypted text is empty"};
	}
	std::string plain{};
	int len=0,plen=0;;
	EVP_CIPHER_CTX *ctx=nullptr;
	unsigned char * decrypted_aux=nullptr;
	try
	{
		if((ctx = EVP_CIPHER_CTX_new())!=nullptr)
		{
			if(EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, ( unsigned char *)SecretKey.data(), (unsigned char*) CTR.data())>0)
			{
				len=0;
				decrypted_aux=(unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*encrypted.size());
				if(decrypted_aux!=nullptr&& EVP_DecryptUpdate(ctx, decrypted_aux, &len, (unsigned char*)encrypted.data(), encrypted.size())>0
				)
				{
					plen=len;
					if(EVP_DecryptFinal_ex(ctx, decrypted_aux + (len), &len)>0)
					{
						plen+=len;
						for(int index=0;index<plen;index++)
						{
							plain.push_back(*(decrypted_aux+index));
						}
					}
				}
				free(decrypted_aux);
				decrypted_aux=nullptr;
			}
		}
		EVP_CIPHER_CTX_free(ctx);
		ctx=nullptr;

	}
	catch(...)
	{
		throw;
	}
	if(!plain.size())
	{
		throw std::runtime_error{"It was not possible decrypt the message"};
	}
	return plain;
}


