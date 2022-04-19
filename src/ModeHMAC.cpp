/*
 * ModeHMAC.cpp
 *
 *  Created on: 21 de jan de 2021
 *      Author: Lucas Dias
 */


#include "PKISymmetric.hpp"
#include <openssl/rand.h>
#include <openssl/evp.h>

using namespace PKI::Symmetric;


void HMACMode::ConfigureKey(std::string newKey="")
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
			delete []key;
			key=nullptr;
			throw std::runtime_error{"It was not possible generate key"};
		}
	}
	else
	{
		SecretKey=newKey;
		if(newKey.size()<32)
		{
			key=new (std::nothrow) unsigned char[32-newKey.size()]{};
			if(key!=nullptr && RAND_bytes(key, sizeof(unsigned char)*(32-newKey.size())))
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

bool HMACMode::VerifyMAC(std::string text, std::string mac)
{
	try
	{
		std::string mac_aux{GenerateMAC(text)};
		if(mac_aux.size()==mac.size() && !std::memcmp(mac.data(), mac_aux.data(), mac.size()))
		{
			return true;
		}
	}
	catch(...)
	{
		return false;
	}



	return false;
}
std::string  HMACMode::GenerateMAC(std::string text)
{
	std::string mac{};
	EVP_PKEY *skey=nullptr;
	size_t req = 0,auxiliar_len=0;
	unsigned char *val=nullptr;
	const EVP_MD* md =  EVP_sha256();
	EVP_MD_CTX*ctx=nullptr;
	skey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, (const unsigned char*) SecretKey.data(),  SecretKey.size());

	if(skey!=nullptr && (ctx = EVP_MD_CTX_create())!=NULL && md != NULL && EVP_DigestInit_ex(ctx, md, NULL)==1  &&
			EVP_DigestSignInit(ctx, NULL, md, NULL, skey) &&  EVP_DigestSignUpdate(ctx, text.data(), text.size()) &&
			EVP_DigestSignFinal(ctx, NULL, &req))
	{
		val = (unsigned char *) OPENSSL_malloc(sizeof(unsigned char)*req);
		if(val!=nullptr &&  EVP_DigestSignFinal(ctx, val, &auxiliar_len))
		{
			for(int index=0;index<auxiliar_len;index++)
			{
				mac.push_back(*(val+index));
			}
		}
	}
	EVP_PKEY_free(skey);
	skey=nullptr;
	EVP_MD_CTX_free(ctx);
	ctx=nullptr;
	OPENSSL_free(val);
	val=nullptr;
	if(mac.size())
	{
		return mac;
	}
	throw std::runtime_error{"It was not possible generate HMAC of"+text};
}

