/*
 * CMAC.cpp
 *
 *  Created on: 5 de jan de 2021
 *      Author: Lucas Dias
 */


#include "PKISymmetric.hpp"
#include <openssl/rand.h>
#include <openssl/evp.h>

using namespace PKI::Symmetric;
void CMACMode::ConfigureKey(std::string newKey)
{

	unsigned char *key=nullptr;
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
			throw std::runtime_error{"It was not possible generate the key"};
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

std::string CMACMode::GenerateMAC(std::string text)
{
	EVP_PKEY *skey=nullptr;
	std::string mac{};
	const EVP_MD*mdx=EVP_sha256();
	EVP_MD_CTX*ctx=nullptr;
	size_t req = 0;
	unsigned char *aux_mac=nullptr;
	bool isOk{false};
	if(SecretKey.size()>=32&& text.size())
	{

		skey=EVP_PKEY_new_CMAC_key(nullptr,(unsigned char*)SecretKey.data(),32,EVP_aes_256_ecb());
		ctx = EVP_MD_CTX_create();
		if(skey!=nullptr && mdx!=nullptr && ctx!=nullptr && EVP_DigestInit_ex(ctx, mdx, NULL)==1 &&
				EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, skey) &&
				EVP_DigestSignUpdate(ctx, text.data(),text.size()) &&
				EVP_DigestSignFinal(ctx,nullptr, &req))
		{

			aux_mac=new (std::nothrow) unsigned char[req]{};
			isOk=(aux_mac!=nullptr && EVP_DigestSignFinal(ctx,aux_mac, &req) );

			if(isOk)
			{

				for(int index=0;index<req;index++)
				{
					mac.push_back(*(aux_mac+index));
				}
				isOk=mac.size();
			}
		}

		EVP_PKEY_free(skey);
		skey=nullptr;
		EVP_MD_CTX_free(ctx);
		ctx=nullptr;
		delete []aux_mac;
		aux_mac=nullptr;
		if(isOk)
		{
			return mac;
		}
	}
	throw std::runtime_error{"It was not possible generate CMAC of "+text};
}
bool CMACMode::VerifyMAC(std::string text, std::string mac)
{
	std::string auxiliar{};
	std::string mac_aux{};
	bool isOk{false};
	if(SecretKey.size() && text.size() && mac.size())
	{
		mac_aux=this->GenerateMAC(text);
		return (mac.size()==mac_aux.size() && !std::memcmp(mac_aux.data(), mac.data(), mac.size()));
	}
	return isOk;
}
