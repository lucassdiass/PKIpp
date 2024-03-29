/*
 * Encrypt.cpp
 *
 *  Created on: 5 de jan de 2021
 *      Author: Lucas Dias
 */
#include "PKISymmetric.hpp"
#include <openssl/rand.h>
using namespace PKI::Symmetric;

void AesECBMode::ConfigureKey(std::string newKey)
{
	unsigned char *key=nullptr,*aux=nullptr;
	if(newKey.empty())
	{
		key=new (std::nothrow) unsigned char[EVP_CIPHER_key_length(EVP_aes_256_ecb())]{};
		if(key!=nullptr && RAND_bytes(key, sizeof(unsigned char)*EVP_CIPHER_key_length(EVP_aes_256_ecb())))
		{
			SecretKey.clear();
			for(int index=0;index<EVP_CIPHER_key_length(EVP_aes_256_ecb());index++)
			{
				SecretKey.push_back(key[index]);
			}
			delete []key;
			key=nullptr;
		}
		else
		{
			throw std::runtime_error{"It was not possible generate the key"};
		}
	}
	else
	{
		SecretKey=newKey;

		if(newKey.size()<EVP_CIPHER_key_length(EVP_aes_256_ecb()))
		{
			key=new (std::nothrow) unsigned char[EVP_CIPHER_key_length(EVP_aes_256_ecb())-newKey.size()]{};
			if(key!=nullptr && RAND_bytes(key, sizeof(unsigned char)*(EVP_CIPHER_key_length(EVP_aes_256_ecb())-newKey.size())))
			{
				for(int index=0;index<(EVP_CIPHER_key_length(EVP_aes_256_ecb())-newKey.size());index++)
				{
					SecretKey.push_back(key[index]);
				}
				delete []key;
				key=nullptr;
			}
		}
	}
}
std::string AesECBMode::EncryptMessage(const std::string& plain)
{
	if(!plain.size())
	{
		throw std::runtime_error{"Invalid plain text"};
	}

	std::string encrypted{}, plain_aux{plain};
	int len=0,ciphertext_len=0;
	float len_aux=0;
	EVP_CIPHER_CTX *ctx=nullptr;
	unsigned char * encrypted_aux=nullptr;
	try
	{
		if((ctx = EVP_CIPHER_CTX_new())!=nullptr)
		{
			if(EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, ( unsigned char *)SecretKey.data(), nullptr)>0
					&& EVP_CIPHER_CTX_set_padding(ctx, 0))
			{
				len_aux=(float)plain.size()/(float)EVP_CIPHER_block_size(EVP_aes_256_ecb());
				len=len_aux;
				if(len_aux!=(float)len)
				{
					throw std::runtime_error{"It was not possible encrypt the message with it is not multiple of 16 bytes"};
				}

				len=(len*EVP_CIPHER_block_size(EVP_aes_256_ecb()));

				encrypted_aux=(unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*(len) );

				if(encrypted_aux!=nullptr &&
						EVP_EncryptUpdate(ctx, encrypted_aux, &ciphertext_len, (unsigned char*)plain_aux.data(), plain_aux.size())>0
				)
				{
					if(EVP_EncryptFinal(ctx, encrypted_aux+ciphertext_len, &len)>0)
					{
						if(len != ciphertext_len) {
							ciphertext_len+=len;
						}
					}
					for(int index=0;index<ciphertext_len;index++)
					{
						encrypted.push_back(*(encrypted_aux+index));
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
std::string AesECBMode::DecryptMessage(const std::string&encrypted)
{
	if(!encrypted.size())
	{
		throw std::runtime_error{"Invalid encrypted text"};
	}
	std::string plain{};
	int len=0,plen=0;;
	EVP_CIPHER_CTX *ctx=nullptr;
	unsigned char * decrypted_aux=nullptr;
	try
	{
		if((ctx = EVP_CIPHER_CTX_new())!=nullptr)
		{
			if(EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, ( unsigned char *)SecretKey.data(), nullptr)>0
					&& EVP_CIPHER_CTX_set_padding(ctx, 0))
			{
				decrypted_aux=(unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*encrypted.size() );
				len = 0;
				if(decrypted_aux!=nullptr&& EVP_DecryptUpdate(ctx, decrypted_aux, &len, (unsigned char*)encrypted.data(), encrypted.size())>0
				)
				{
					plen=len;
					if(EVP_DecryptFinal_ex(ctx, decrypted_aux, &len)>0)
					{
						plen+=len;
					}
					else {
						plen = 0;
					}
					for(int index=0;index<plen; index++)
					{
						plain.push_back(*(decrypted_aux+index));
					}
				}
				OPENSSL_free(decrypted_aux);
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
