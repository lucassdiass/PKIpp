/*
 * CMAC.cpp
 *
 *  Created on: 5 de jan de 2021
 *      Author: Lucas Vargas Dias
 */


#include "PKISymmetric.hpp"
#include <openssl/rand.h>
#include <openssl/evp.h>

using namespace PKI::Symmetric;
void CMACMode::ConfigureKey(std::string newKey)
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

std::string CMACMode::GenerateMAC(std::string text)
{
	EVP_PKEY *skey=nullptr;
	std::string mac{};
	EVP_MD_CTX*mdx=nullptr;
	size_t req = 0,vlen=0;
	unsigned char *aux_mac=nullptr;
	bool isOk{false};
	if(SecretKey.size()&& text.size())
	{
		skey=EVP_PKEY_new_CMAC_key(nullptr,(unsigned char*)SecretKey.data(), SecretKey.size(),EVP_aes_256_ecb());
		mdx=EVP_MD_CTX_new();
		if(skey!=nullptr && mdx!=nullptr && EVP_DigestSignInit(mdx, nullptr, EVP_sha256(), nullptr, skey) &&
				EVP_DigestSignUpdate(mdx,(unsigned char*)text.data(),text.size()) && EVP_DigestSignFinal(mdx,nullptr, &req))
		{
			aux_mac=new unsigned char[req];
			isOk=(aux_mac!=nullptr && EVP_DigestSignFinal(mdx,aux_mac, &req) );

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
		EVP_MD_CTX_free(mdx);
		mdx=nullptr;
		delete []aux_mac;
		aux_mac=nullptr;
		if(isOk)
		{
			return mac;
		}
	}
	throw std::runtime_error{"Não foi possível gerar CMAC da mensagem "+text};
}
bool CMACMode::VerifyMAC(std::string text, std::string mac)
{
	EVP_PKEY* skey=nullptr;
	unsigned int *len=nullptr;
	EVP_MD_CTX*mdx=nullptr;
	std::string auxiliar{};
	std::string mac_aux{};
	size_t req = 0,vlen=0;
	unsigned char *aux_mac=nullptr;
	bool isOk{false};
	if(SecretKey.size() && text.size() && mac.size())
	{
		//auxiliar=text;
		//auxiliar.append(signature);
		len=new unsigned int;
		if(len!=nullptr)
		{
			skey=EVP_PKEY_new_CMAC_key(nullptr,(unsigned char*)SecretKey.data(), SecretKey.size(),EVP_aes_256_ecb());
			mdx=EVP_MD_CTX_new();
			if(skey!=nullptr && mdx!=nullptr && EVP_DigestSignInit(mdx, nullptr, EVP_sha256(), nullptr, skey) &&
					EVP_DigestSignUpdate(mdx,(unsigned char*)text.data(),text.size()) && EVP_DigestSignFinal(mdx,nullptr, &req))
			{
				aux_mac=new unsigned char[req];
				isOk=(aux_mac!=nullptr && EVP_DigestSignFinal(mdx,aux_mac, &req));

				if(isOk)
				{
					for(int index=0;index<req;index++)
					{
						mac_aux.push_back(*(aux_mac+index));
					}
					isOk= (mac_aux.size()==mac.size()) && !(std::strncmp(mac_aux.data(), mac.data(), mac.size()));
				}
			}
			EVP_PKEY_free(skey);
			skey=nullptr;
			EVP_MD_CTX_free(mdx);
			mdx=nullptr;
			delete []aux_mac;
			aux_mac=nullptr;
		}
	}
	delete len;
	len=nullptr;
	return isOk;
}
