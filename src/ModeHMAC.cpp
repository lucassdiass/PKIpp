/*
 * ModeHMAC.cpp
 *
 *  Created on: 21 de jan de 2021
 *      Author: Lucas Vargas Dias
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
			delete []key;
			key=nullptr;
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

bool HMACMode::VerifyMAC(std::string text, std::string mac)
{
	std::string mac_aux;
	if(text.size()&&mac.size())
	{
		try
		{
			mac_aux=GenerateMAC(text);
			if(mac_aux.size()==mac.size() && !strncmp(mac_aux.data(), mac.data(),mac.size()))
			{
				return true;
			}
		}
		catch(...)
		{
			return false;
		}

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
	// EVP_sha256()
	skey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, (const unsigned char*) SecretKey.data(),  SecretKey.size());

	if(skey!=nullptr && (ctx = EVP_MD_CTX_create())!=NULL && md != NULL && EVP_DigestInit_ex(ctx, md, NULL)==1  &&
			EVP_DigestSignInit(ctx, NULL, md, NULL, skey) &&  EVP_DigestSignUpdate(ctx, text.data(), text.size()) && EVP_DigestSignFinal(ctx, NULL, &req))
	{
		//*auxiliar_vlen= req;
		val = (unsigned char *) OPENSSL_malloc(sizeof(unsigned char)*req);
		if(val!=nullptr &&  EVP_DigestSignFinal(ctx, val, &auxiliar_len))
		{
			for(int index=0;index<req;index++)
			{
				mac.push_back(*(val+index));
			}
		}
	}
	//	isOk=mac.size();
	EVP_PKEY_free(skey);
	skey=nullptr;
	EVP_MD_CTX_free(ctx);
	ctx=nullptr;
	delete []val;
	val=nullptr;
	if(mac.size())
	{
		return mac;
	}
	throw std::runtime_error{"Não foi possível gerar HMAC da mensagem "+text};
}

