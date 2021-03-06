/*
 * OFB.cpp
 *
 *  Created on: 5 de jan de 2021
 *      Author: Lucas Dias
 */
#include "PKISymmetric.hpp"
#include <openssl/rand.h>
using namespace PKI::Symmetric;

void AesOFBMode::ConfigureKey(std::string newKey="")
{
	unsigned char *key=nullptr;
	if(newKey.empty())
	{
		key=new (std::nothrow) unsigned char[EVP_CIPHER_key_length(EVP_aes_256_ofb())]{};
		if(key!=nullptr)
		{
			if(RAND_bytes(key, sizeof(unsigned char)*EVP_CIPHER_key_length(EVP_aes_256_ofb())))
			{
				SecretKey.clear();
				for(int index=0;index<EVP_CIPHER_key_length(EVP_aes_256_ofb());index++)
				{
					SecretKey.push_back(key[index]);
				}
			}
			delete []key;
			key=nullptr;
		}
		else
		{
			throw std::runtime_error{"It was not possible generate key"};
		}
	}
	else
	{
		SecretKey=newKey;

		if(newKey.size()<EVP_CIPHER_key_length(EVP_aes_256_ofb()))
		{
			key=new  (std::nothrow) unsigned char[EVP_CIPHER_key_length(EVP_aes_256_ofb())-newKey.size()]{};
			if(key!=nullptr && RAND_bytes(key, sizeof(unsigned char)*(EVP_CIPHER_key_length(EVP_aes_256_ofb())-newKey.size())))
			{
				for(int index=0;index<(EVP_CIPHER_key_length(EVP_aes_256_ofb())-newKey.size());index++)
				{
					SecretKey.push_back(key[index]);
				}
			}
			delete []key;
			key=nullptr;
		}
	}
}
void AesOFBMode::ConfigureIV(std::string newIV="")
{
	unsigned char *iv=nullptr;
	if(newIV.empty())
	{
		iv=new (std::nothrow) unsigned char[EVP_CIPHER_iv_length(EVP_aes_256_ofb())]{};
		if(iv!=nullptr)
		{
			if(RAND_bytes(iv, sizeof(unsigned char)*EVP_CIPHER_iv_length(EVP_aes_256_ofb())))
			{
				IV.clear();
				for(int index=0;index<EVP_CIPHER_iv_length(EVP_aes_256_ofb());index++)
				{
					IV.push_back(iv[index]);
				}
			}
			delete []iv;
			iv=nullptr;
		}
		else
		{
			throw std::runtime_error{"It was not possible generate IV"};
		}
	}
	else
	{
		IV=newIV;
		if(IV.size()<EVP_CIPHER_iv_length(EVP_aes_256_ofb()))
		{
			iv=new (std::nothrow) unsigned char[EVP_CIPHER_iv_length(EVP_aes_256_cfb128())-newIV.size()]{};
			if(iv!=nullptr && RAND_bytes(iv, sizeof(unsigned char)*(EVP_CIPHER_iv_length(EVP_aes_256_cfb128())-newIV.size())))
			{
				for(int index=0;index<(EVP_CIPHER_iv_length(EVP_aes_256_cfb128())-newIV.size());index++)
				{
					IV.push_back(iv[index]);
				}
			}
			delete []iv;
			iv=nullptr;
		}
	}
}

std::string AesOFBMode::EncryptMessage(const std::string& plain)
{
	if(!plain.size())
	{
		throw std::runtime_error{"Invalid plain text"};
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
			if(EVP_EncryptInit_ex(ctx, EVP_aes_256_ofb(), nullptr, ( unsigned char *)SecretKey.data(), (unsigned char*) IV.data())>0)
			{
				len_aux=(float)plain.size()/(float)EVP_CIPHER_block_size(EVP_aes_256_ofb());
				len=len_aux;
				if(len_aux!=(float)len)
				{
					len=(len*EVP_CIPHER_block_size(EVP_aes_256_ofb()))  +    EVP_CIPHER_block_size(EVP_aes_256_ofb());
				}
				else
				{
					len=(len*EVP_CIPHER_block_size(EVP_aes_256_ofb()));
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
		std::runtime_error{"It was not possible encrypt message"};
	}
	return encrypted;
}
std::string AesOFBMode::DecryptMessage(const std::string&encrypted)
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
			if(EVP_DecryptInit_ex(ctx, EVP_aes_256_ofb(), nullptr, ( unsigned char *)SecretKey.data(), (unsigned char*) IV.data())>0)
			{
				len=0;
				decrypted_aux=(unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*(encrypted.size()) );
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
		std::runtime_error{"It was not possible decrypt message"};
	}
	return plain;
}


