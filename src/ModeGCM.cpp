/*
 * ModeGCM.cpp
 *
 *  Created on: 6 de jan de 2021
 *      Author: Lucas Dias
 */
#include "PKISymmetric.hpp"
#include <openssl/rand.h>
using namespace PKI::Symmetric;

void AesGCMMode::ConfigureKey(std::string newKey)
{

	unsigned char *key=nullptr,*aux=nullptr;
	if(newKey.empty())
	{
		key=new (std::nothrow) unsigned char[32]{};
		if(key!=nullptr && RAND_bytes(key, sizeof(unsigned char)*32))
		{
			SecretKey.clear();
			for(int index=0;index<32;index++)
			{
				SecretKey.push_back(key[index]);
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

		if(newKey.size()<32)
		{
			key=new unsigned char[32-newKey.size()];
			if(key!=nullptr&&	RAND_bytes(key, sizeof(unsigned char)*(32-newKey.size())))
			{
				for(int index=0;index<(32-newKey.size());index++)
				{
					SecretKey.push_back(key[index]);
				}
				delete []key;
				key=nullptr;
			}
		}
	}
}

void AesGCMMode::ConfigureIV(std::string newIV)
{
	unsigned char *iv=nullptr;
	if(newIV.empty())
	{
		iv=new (std::nothrow) unsigned char[32]{};
		if(iv!=nullptr && RAND_bytes(iv, sizeof(unsigned char)*32))
		{
			IV.clear();
			for(int index=0;index<32;index++)
			{
				IV.push_back(iv[index]);
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
		if(newIV.size()<32)
		{
			iv=new (std::nothrow) unsigned char[32-IV.size()]{};
			if(iv!=nullptr && RAND_bytes(iv, sizeof(unsigned char)*(32-IV.size())))
			{
				for(int index=0;index<(32-IV.size());index++)
				{
					SecretKey.push_back(iv[index]);
				}
				delete []iv;
				iv=nullptr;
			}
		}
	}
}

std::string AesGCMMode::EncryptAuthMessage(std::string plain, std::string&encrypted )
{
	if(!plain.size())
	{
		throw std::runtime_error{"Invalid plain text"};
	}
	std::string mac{};
	int len=0,ciphertext_len=0;
	float len_aux=0;
	unsigned char tag[16];
	EVP_CIPHER_CTX *ctx=nullptr;
	unsigned char * encrypted_aux=nullptr;
	try
	{
		if((ctx = EVP_CIPHER_CTX_new())!=nullptr &&
				EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) &&
				EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV.size(), nullptr)&&
				EVP_EncryptInit_ex(ctx,nullptr, nullptr, (unsigned char*)SecretKey.data(), (unsigned char*)IV.data()))
		{
			len_aux=(float)plain.size()/(float)EVP_CIPHER_block_size(EVP_aes_256_gcm());

			len=len_aux;
			if(len_aux!=(float)len)
			{
				len=(len*EVP_CIPHER_block_size(EVP_aes_256_gcm()))  +    EVP_CIPHER_block_size(EVP_aes_256_gcm());
			}
			else
			{
				len=(len*EVP_CIPHER_block_size(EVP_aes_256_gcm()));
			}

			if(
					(encrypted_aux=(unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*(len) ))!=nullptr &&
					EVP_EncryptUpdate(ctx, encrypted_aux, &len, (unsigned char*)plain.data(), plain.size())>0 )
			{

				ciphertext_len=len;
				if(EVP_EncryptFinal_ex(ctx, encrypted_aux + len, &len)>0 &&
						EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
				{
					ciphertext_len+=len;
					encrypted.clear();
					for(int index=0;index<ciphertext_len;index++)
					{
						encrypted.push_back(*(encrypted_aux+index));
					}
					for(int j=0;j<16;j++)
					{
						mac.push_back(tag[j]);
					}
				}
			}
			OPENSSL_free(encrypted_aux);
			encrypted_aux=nullptr;

		}

		EVP_CIPHER_CTX_free(ctx);
	}
	catch(...)
	{
		throw;
	}
	if(!mac.size())
	{
		std::runtime_error{"It was not possible encrypt and authenticate the message"};
	}
	return mac;
}
bool AesGCMMode::DecryptVerifyMessage(std::string encrypted,  std::string mac, std::string &plain)
{
	if(!encrypted.size())
	{
		throw std::runtime_error{"Invalid encrypted text"};
	}
	int len=0,plen=0;;
	EVP_CIPHER_CTX *ctx=nullptr;
	bool ret{false};
	unsigned char * decrypted_aux=nullptr;
	try
	{
		plain.clear();
		if((ctx = EVP_CIPHER_CTX_new())!=nullptr &&
			EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)  &&
			EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV.size(), nullptr) &&
			EVP_DecryptInit_ex(ctx,nullptr, nullptr, (unsigned char*)SecretKey.data(), (unsigned char*)IV.data()))
		{

			plen=len;
			decrypted_aux=(unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*(encrypted.size()+mac.size()));
			if(decrypted_aux!=nullptr&& EVP_DecryptUpdate(ctx, decrypted_aux, &len, (unsigned char*)encrypted.data(), encrypted.size())>0 &&
					EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)mac.data())
			)
			{

				plen=len;
				if((ret=EVP_DecryptFinal_ex(ctx, decrypted_aux + plen, &len)))
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

		EVP_CIPHER_CTX_free(ctx);
		ctx=nullptr;

	}
	catch(...)
	{
		throw;
	}
	return ret;
}
