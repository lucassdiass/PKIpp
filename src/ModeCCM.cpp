/*
 * ModeCCM.cpp
 *
 *  Created on: 6 de jan de 2021
 *      Author: Lucas Vargas Dias
 */

#include "PKISymmetric.hpp"
#include <openssl/rand.h>
using namespace PKI::Symmetric;

void AesCCMMode::ConfigureKey(std::string newKey)
{

	unsigned char *key=nullptr,*aux=nullptr;
	if(newKey.empty())
	{
		key=new unsigned char[32];
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
			throw std::runtime_error{"Nao foi possivel gerar chave"};
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

void AesCCMMode::ConfigureIV(std::string newIV)
{
	unsigned char *iv=nullptr;
	if(newIV.empty())
	{
		iv=new unsigned char[7];
		std::memset(iv, 0x00,7);
		if(iv!=nullptr && RAND_bytes(iv, sizeof(unsigned char)*7))
		{
			IV.clear();
			for(int index=0;index<7;index++)
			{
				IV.push_back(iv[index]);
			}
			delete []iv;
			iv=nullptr;
		}
		else
		{
			throw std::runtime_error{"Nao foi possivel gerar chave"};
		}
	}
	else
	{
		IV=newIV;
		if(newIV.size()<7)
		{
			iv=new unsigned char[7-IV.size()];
			if(iv!=nullptr&&	RAND_bytes(iv, sizeof(unsigned char)*(7-IV.size())))
			{
				for(int index=0;index<(7-IV.size());index++)
				{
					SecretKey.push_back(iv[index]);
				}
				delete []iv;
				iv=nullptr;
			}
		}
	}
}

std::string AesCCMMode::EncryptAuthMessage(std::string plain, std::string&encrypted )
{
	if(!plain.size())
	{
		throw std::runtime_error{"Texto inválido para cifragem"};
	}
	std::string mac{};
	int len=0,ciphertext_len=0;
	float len_aux=0;
	unsigned char tag[12];
	EVP_CIPHER_CTX *ctx=nullptr;
	unsigned char * encrypted_aux=nullptr;
	try
	{
		//auto secret=GenerateSecret();
		if((ctx = EVP_CIPHER_CTX_new())!=nullptr &&
				EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(), nullptr, nullptr, nullptr) &&
				EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, nullptr)&&
				EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 12, NULL)&&
				EVP_EncryptInit_ex(ctx,nullptr, nullptr, (unsigned char*)SecretKey.data(), (unsigned char*)IV.data()))// ( unsigned char *)SecretKey.data(), (unsigned char*) IV.data())>0)
		{
			//	len=EVP_CIPHER_block_size(EVP_aes_256_ecb());
			len_aux=(float)plain.size()/(float)EVP_CIPHER_block_size(EVP_aes_256_ccm());
			//len=len*EVP_CIPHER_block_size(EVP_aes_256_ecb());
			len=len_aux;
			if(len_aux!=(float)len)
			{
				len=(len*EVP_CIPHER_block_size(EVP_aes_256_ccm()))  +    EVP_CIPHER_block_size(EVP_aes_256_ccm());
			}
			else
			{
				len=(len*EVP_CIPHER_block_size(EVP_aes_256_ccm()));
			}
			//	len=0;
			if(
					(encrypted_aux=(unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*(len) ))!=nullptr &&
					EVP_EncryptUpdate(ctx, encrypted_aux, &len, (unsigned char*)plain.data(), plain.size())>0 )
			{

				ciphertext_len=len;
				if(EVP_EncryptFinal_ex(ctx, encrypted_aux + len, &len)>0 &&
						EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 12, tag))
				{
					ciphertext_len+=len;
					encrypted.clear();
					for(int index=0;index<ciphertext_len;index++)
					{
						encrypted.push_back(*(encrypted_aux+index));
					}
					for(int j=0;j<12;j++)
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
		std::runtime_error{"Não foi possível cifrar e autenticar a mensagem"};
	}
	return mac;
}
bool AesCCMMode::DecryptVerifyMessage(std::string encrypted,  std::string mac, std::string &plain)
{
	if(!encrypted.size())
	{
		throw std::runtime_error{"Texto inválido para decifragem"};
	}
	int len=0,plen=0;;
	EVP_CIPHER_CTX *ctx=nullptr;
	bool ret{false};
	unsigned char * decrypted_aux=nullptr;
	try
	{
		plain.clear();
		if((ctx = EVP_CIPHER_CTX_new())!=nullptr &&
				EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), nullptr, nullptr, nullptr)  &&
				EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, nullptr) &&
				EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 12, (void*)mac.data())&&

				EVP_DecryptInit_ex(ctx,nullptr, nullptr, (unsigned char*)SecretKey.data(), (unsigned char*)IV.data()))
		{

			//encrypted.size();//EVP_CIPHER_block_size(EVP_aes_256_ecb());
			plen=len;
			decrypted_aux=(unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*(encrypted.size()+mac.size()));
			if(decrypted_aux!=nullptr&& EVP_DecryptUpdate(ctx, decrypted_aux, &len, (unsigned char*)encrypted.data(), encrypted.size())>0 )
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

