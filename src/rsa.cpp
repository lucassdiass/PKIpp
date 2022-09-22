/*
 * rsa.cpp
 *
 *  Created on: 7 de ago de 2020
 *      Author: Lucas Dias
 */
#include "PKI++.hpp"
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
using namespace PKI;
PKIRSA::PKIRSA(unsigned int length) : InterfacePKI::SignatureDigital{},InterfacePKI::Confidentiality{},InterfacePKI::StreamStore{},
		PubKey{nullptr}, PrvKey{nullptr}
{
	if(length<3072)
	{
		length=3072;
	}
	EVP_PKEY * PairKey=nullptr;
	BIO*bp_public=nullptr,*bp_private=nullptr;
	int ret=1,round=0;
	auto pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
	if(pctx==nullptr||pctx==NULL)
	{
		throw std::runtime_error{"Error in initialization of RSA keys"};
	}
	while(ret==1 && round<4)
	{
		switch(round)
		{
		case 0 :
		{
			ret=EVP_PKEY_keygen_init(pctx);
			break;
		}
		case 1:
		{
			ret=EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, length);
			break;
		}
		case 2:
		{
			PairKey = EVP_PKEY_new();
			if(PairKey == nullptr)
			{
				ret=0;
			}
			break;
		}
		case 3 :
		{
			ret=EVP_PKEY_keygen(pctx,&PairKey);
			break;
		}
		}
		round++;
	}
	EVP_PKEY_CTX_free(pctx);
	pctx=nullptr;
	if(ret!=1)
	{
		EVP_PKEY_free(PairKey);
		PairKey=nullptr;
		throw std::runtime_error{"Error in the generation keys"};

	}
	ret=0;
	bp_public=BIO_new(BIO_s_mem());
	bp_private=BIO_new(BIO_s_mem());

	if(bp_private!=nullptr && bp_public!=nullptr )
	{
		if(PEM_write_bio_PUBKEY(bp_public,PairKey)>0 &&  PEM_write_bio_PrivateKey(bp_private,PairKey,nullptr, nullptr, 0, 0, nullptr)>0)
		{
			PubKey = EVP_PKEY_ptr(PEM_read_bio_PUBKEY(bp_public,nullptr,nullptr,nullptr), EVP_PKEY_free);
			PrvKey = EVP_PKEY_ptr(PEM_read_bio_PrivateKey(bp_private,nullptr,nullptr, nullptr), EVP_PKEY_free);

			if( PubKey.get() != nullptr && PrvKey.get()!=nullptr)
			{
				ret=1;
			}
		}
	}
	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	EVP_PKEY_free(PairKey);
	PairKey = nullptr;
	if(ret != 1)
	{
		throw std::runtime_error{"Error in the generation keys"};
	}
}



PKIRSA::PKIRSA(std::string file_pub_path, bool isfile) : InterfacePKI::SignatureDigital{},InterfacePKI::Confidentiality{},InterfacePKI::StreamStore{},
		PubKey(nullptr)
{
	if(!file_pub_path.size())
	{
		throw std::runtime_error{"Invalid path"};
	}
	int ret=0;
	BIO * bp_public=nullptr;
	std::ifstream fs{file_pub_path};
	if(isfile)
	{
		if(fs)
		{
			fs.close();
			bp_public = BIO_new_file(file_pub_path.c_str(), "r+");
			if( bp_public !=nullptr)
			{
				ret=1;
			}
		}
	}
	else
	{
		bp_public=BIO_new(BIO_s_mem());
		if( bp_public !=nullptr && BIO_write(bp_public,(void *)file_pub_path.c_str(),file_pub_path.size()))
		{
			ret=1;
		}
	}

	if(ret)
	{
		PubKey = EVP_PKEY_ptr(PEM_read_bio_PUBKEY(bp_public,nullptr,nullptr,nullptr), EVP_PKEY_free);
	}
	BIO_free_all(bp_public);
	if(PubKey.get() == nullptr)
	{
		throw std::runtime_error{"It was not possible load the key from "+file_pub_path};
	}

}
PKIRSA::PKIRSA(std::string file_pub_path, std::string file_prv_path, bool arefile=true) : PKIRSA{file_pub_path, arefile}
{
	if(!file_prv_path.size())
	{
		throw std::runtime_error{"Invalid path"};
	}
	int ret=0;
	BIO*bp_private=nullptr;
	std::ifstream fs{file_prv_path};
	if(arefile)
	{
		if(fs)
		{
			fs.close();
			bp_private = BIO_new_file(file_prv_path.c_str(), "r+");
			if(bp_private != nullptr)
			{
				ret = 1;
			}
		}
	}
	else
	{
		if((bp_private=BIO_new(BIO_s_mem()))!=nullptr && BIO_write(bp_private,(void*)file_prv_path.c_str(),file_prv_path.size()))
		{
			ret=1;
		}

	}
	if(ret)
	{
		PrvKey = EVP_PKEY_ptr(PEM_read_bio_PrivateKey(bp_private,nullptr,nullptr,nullptr),EVP_PKEY_free) ;
	}
	BIO_free_all(bp_private);
	if(PrvKey.get() == nullptr)
	{
		throw std::runtime_error{"It was not possible load the key from "+file_prv_path};
	}
}
std::string PKIRSA::GenerateRequest(const request_data& dados)
{
	X509_REQ *x509_req=nullptr;
	X509_NAME *x509_name=nullptr;
	std::string request_str{};
	bool ret_req=false;
	char* request=nullptr;
	size_t len=0,success=0;
	BIO * out_request=nullptr;
	x509_req=X509_REQ_new();
	if(x509_req==nullptr || X509_REQ_set_version(x509_req,3)<1 || (x509_name= X509_REQ_get_subject_name(x509_req))==nullptr)
	{
		X509_REQ_free(x509_req);
		throw std::runtime_error {"It was not possible to set the version number"};
	}
	if(dados.szCountry.size() &&dados.szProvince.size() && dados.szCity.size()&&dados.szOrganization.size()&&dados.szCommon.size() )
	{
		ret_req=X509_NAME_add_entry_by_txt(x509_name,"C",MBSTRING_ASC, (const unsigned char*)dados.szCountry.c_str(),-1,-1,0) &&
				X509_NAME_add_entry_by_txt(x509_name,"ST",MBSTRING_ASC, (const unsigned char*)dados.szProvince.c_str(),-1,-1,0) &&
				X509_NAME_add_entry_by_txt(x509_name,"L",MBSTRING_ASC, (const unsigned char*)dados.szCity.c_str(),-1,-1,0) &&
				X509_NAME_add_entry_by_txt(x509_name,"O",MBSTRING_ASC, (const unsigned char*)dados.szOrganization.c_str(),-1,-1,0) &&
				X509_NAME_add_entry_by_txt(x509_name,"CN",MBSTRING_ASC, (const unsigned char*)dados.szCommon.c_str(),-1,-1,0) &&
				X509_REQ_set_pubkey(x509_req,this->PubKey.get())&&
				X509_REQ_sign(x509_req,this->PrvKey.get(),EVP_sha256());
	}
	if(!ret_req)
	{
		X509_REQ_free(x509_req);
		throw std::runtime_error {"Invalid data to request certificate"};
	}

	out_request=BIO_new(BIO_s_mem());
	if(out_request!=nullptr && PEM_write_bio_X509_REQ(out_request,x509_req))
	{

		if(BIO_read_ex(out_request,nullptr,-1,&len)&&len>0)
		{
			request=new char[len];
			if(request!=nullptr && BIO_read_ex(out_request,(void*)request,len,&success) && len==success)
			{
				request_str=std::string{request,len};
			}
		}
	}

	delete []request;
	BIO_free_all(out_request);
	X509_REQ_free(x509_req);
	if(!request_str.size())
	{
		throw std::runtime_error{"It was not possible generate the requesition of certificate"};
	}
	return request_str;
}


void PKIRSA::SavePubKey(std::string file_pub_path)
{

	bool ok=false;
	BIO*bp_public = nullptr;
	if(this->PubKey.get()==nullptr)
	{
		throw std::runtime_error{"Public key is null"};
	}
	if(!file_pub_path.size())
	{
		throw std::runtime_error{"Invalid path"};
	}
	ok=((bp_public = BIO_new_file(file_pub_path.c_str(), "w+"))!=nullptr && PEM_write_bio_PUBKEY(bp_public,this->PubKey.get())>0);
	BIO_free_all(bp_public);
	if(!ok)
	{
		throw std::runtime_error{"It was not possible store the key"};
	}
}
void PKIRSA::SavePrvKey(std::string file_prv_path)
{
	BIO*bp_private = nullptr;
	bool ok=false;;
	if(PrvKey.get() == nullptr)
	{
		throw std::runtime_error{"Private key is null"};
	}

	if(!file_prv_path.size())
	{
		throw std::runtime_error{"Invalid path"};
	}
	ok=((bp_private = BIO_new_file(file_prv_path.c_str(), "w+"))!=nullptr &&
			PEM_write_bio_PrivateKey(bp_private,this->PrvKey.get(),NULL, NULL, 0, 0, NULL)>0);
	BIO_free_all(bp_private);
	if(!ok)
	{
		throw std::runtime_error{"It was not possible store the key"};
	}
}

std::string PKIRSA::SignMessage(std::string message)
{
	size_t length=0;
	int ret=1, round=0;
	std::string signature{};
	unsigned char * signature_aux=nullptr;
	EVP_MD_CTX *mdctx = nullptr;
	while(ret==1 && round<5)
	{
		switch(round)
		{
		case 0 :
		{
			mdctx = EVP_MD_CTX_create();
			if(mdctx == nullptr)
			{
				ret=0;
			}
			break;
		}
		case 1 :
		{
			ret=EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr,this->PrvKey.get());
			break;
		}
		case 2:
		{
			ret=EVP_DigestSignUpdate(mdctx, message.data(), message.size());

			break;
		}
		case 3:
		{

			ret=EVP_DigestSignFinal(mdctx,nullptr,&length);

			break;
		}
		case 4:
		{

			signature_aux=(unsigned char*)OPENSSL_malloc(sizeof(unsigned char) * (length));
			ret=0;
			if(signature_aux!=nullptr)
			{
				ret=EVP_DigestSignFinal(mdctx, signature_aux, &length);
			}
			break;
		}
		}
		round++;
	}
	EVP_MD_CTX_destroy(mdctx);
	if(ret!=1)
	{
		OPENSSL_free(signature_aux);
		signature_aux=nullptr;
		throw std::runtime_error{"It was not possible sign "+message};
	}
	for(int index=0;index<length;index++)
	{
		signature.push_back(*(signature_aux+index));
	}
	OPENSSL_free(signature_aux);
	return signature;
}
bool PKIRSA::VerifySignatureMessage(std::string message, std::string signature)
{
	EVP_MD_CTX *mdctx = nullptr;
	int ret=0;
	mdctx = EVP_MD_CTX_create();
	if(mdctx != nullptr)
	{
		if(EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr,this->PubKey.get()))
		{
			if(EVP_DigestVerifyUpdate(mdctx, message.data(), message.size()))
			{
				ret=EVP_DigestVerifyFinal(mdctx,(unsigned char*)signature.data(),signature.size());
			}
		}
		EVP_MD_CTX_destroy(mdctx);
	}
	return ret==1;
}
std::string PKIRSA::EncryptMessage(const std::string& plain)
{
	if(!plain.size())
	{
		throw std::runtime_error{"Plain text is empty"};
	}
	EVP_PKEY_CTX * params=nullptr;
	size_t len=0,success=0;
	std::string encrypted{};
	char * encrypted_aux=nullptr;
	params = EVP_PKEY_CTX_new(this->PubKey.get(), NULL);
	if(params!=nullptr && EVP_PKEY_encrypt_init(params))
	{
		if(EVP_PKEY_encrypt(params,nullptr,&len,(unsigned char*)plain.data(),plain.size()) && len>0 )
		{
			encrypted_aux=( char*)OPENSSL_malloc(sizeof( char) * (len));
			if(encrypted_aux!=nullptr &&
					EVP_PKEY_encrypt(params,(unsigned char*)encrypted_aux,&success,(unsigned char*)plain.data(),plain.size()))
			{
				for(int index=0;index<len;index++)
				{
					encrypted.push_back(*(encrypted_aux+index));
				}
			}
		}
	}
	EVP_PKEY_CTX_free(params);
	params=nullptr;
	OPENSSL_free(encrypted_aux);
	if(!encrypted.size())
	{
		throw std::runtime_error{"Error in CTX RSA"};
	}
	return encrypted;
}
std::string PKIRSA::DecryptMessage(const std::string&encrypted)
{
	if(!encrypted.size())
	{
		throw std::runtime_error{"Encrypted text is empty"};
	}
	EVP_PKEY_CTX * params=nullptr;
	size_t len=0;
	std::string plain{};
	char * plain_aux=nullptr;
	params=EVP_PKEY_CTX_new(PrvKey.get(), nullptr);
	if(params!=nullptr && EVP_PKEY_decrypt_init(params))
	{
		if(EVP_PKEY_decrypt(params,nullptr,&len,(unsigned char*)encrypted.data(),encrypted.size()) && len)
		{
			plain_aux=( char*)OPENSSL_malloc(sizeof( char) * (len));
			if(plain_aux!=nullptr &&
					EVP_PKEY_decrypt(params,(unsigned char*)plain_aux,&len,(unsigned char*)encrypted.data(),encrypted.size())>0 )
			{
				for(int index=0;index<len;index++)
				{
					plain.push_back(*(plain_aux+index));
				}
			}
		}
	}
	OPENSSL_free(plain_aux);
	EVP_PKEY_CTX_free(params);
	params=nullptr;
	if(!plain.size())
	{
		throw std::runtime_error{"Error in CTX RSA"};
	}
	return plain;
}
std::string  PKIRSA::SavePrvKey()
{
	BIO*bp_private = nullptr;
	std::string prvkeystr{};
	size_t  len=0, success=0;
	char *prvkeystr_aux=nullptr;
	bp_private=BIO_new(BIO_s_mem());

	if( bp_private!=nullptr && PEM_write_bio_PrivateKey(bp_private,PrvKey.get(),nullptr, nullptr, 0, 0, nullptr)>0)
	{
		if(BIO_read_ex(bp_private,nullptr,-1,&len) && len>0)
		{
			prvkeystr_aux=new char[len];
			if(prvkeystr_aux!=nullptr)
			{
				if(BIO_read_ex(bp_private,(void*)prvkeystr_aux,len,&success)&&len==success)
				{
					prvkeystr=std::string{prvkeystr_aux,success};
				}
			}
		}
	}
	BIO_free_all(bp_private);
	bp_private=nullptr;
	delete []prvkeystr_aux;
	prvkeystr_aux=nullptr;
	if(!prvkeystr.size())
	{
		throw std::runtime_error{"It was not possible convert the private key to string"};
	}
	return prvkeystr;
}
std::string  PKIRSA::SavePubKey()
{
	BIO*bp_public = nullptr;
	std::string pubkeystr{};
	size_t  len=0, success=0;
	char *pubkeystr_aux=nullptr;
	bp_public=BIO_new(BIO_s_mem());
	if( bp_public!=nullptr &&PEM_write_bio_PUBKEY(bp_public,PubKey.get())>0)
	{
		if(BIO_read_ex(bp_public,nullptr,-1,&len) && len>0)
		{
			pubkeystr_aux=new char[len];
			if(pubkeystr_aux!=nullptr && BIO_read_ex(bp_public,(void*)pubkeystr_aux,len,&success)&&len==success)
			{
				pubkeystr=std::string{pubkeystr_aux,success};
			}
		}
	}
	BIO_free_all(bp_public);
	bp_public=nullptr;
	delete []pubkeystr_aux;
	pubkeystr_aux=nullptr;
	if(!pubkeystr.size())
	{
		throw std::runtime_error{"It was not possible convert the public key to string"};
	}
	return pubkeystr;
}
std::string PKIRSA::SelfSign(std::string request)
{
	X509_REQ *requisition=nullptr;
	std::string Certificate_str{};
	char *certificate_aux=nullptr;
	X509 *certificate=nullptr;
	ASN1_INTEGER *aserial=nullptr;
	size_t lenght=0, writed=0;

	BIO * bio_requisition=nullptr,* bio_certificate=nullptr;

	if( (bio_requisition=BIO_new(BIO_s_mem()))!=nullptr && 	BIO_write(bio_requisition, request.data(), request.size()) &&
			(requisition=PEM_read_bio_X509_REQ(bio_requisition,nullptr,nullptr,nullptr))!=nullptr )
	{
		if(X509_REQ_verify(requisition,this->PubKey.get()))
		{
			certificate=X509_new();
			aserial=ASN1_INTEGER_new();
			if(certificate!=nullptr && X509_set_version(certificate,2) && aserial!=nullptr && ASN1_INTEGER_set(aserial,1) &&
					X509_set_subject_name(certificate,X509_REQ_get_subject_name(requisition)) &&
					X509_set_issuer_name(certificate,X509_REQ_get_subject_name(requisition)) &&
					X509_set_pubkey(certificate,this->PubKey.get()) &&
					X509_gmtime_adj(X509_get_notBefore(certificate),0)&&
					X509_gmtime_adj(X509_get_notAfter(certificate),365*3*24*60*60)&&
					this->PrvKey!=nullptr &&
					X509_sign(certificate,this->PrvKey.get(), EVP_sha256()))
			{
				bio_certificate=BIO_new(BIO_s_mem());
				if(bio_certificate!=nullptr && PEM_write_bio_X509(bio_certificate,certificate))
				{
					if(BIO_read_ex(bio_certificate,nullptr,-1,&lenght) && lenght)
					{
						certificate_aux=new char[lenght];
						if(certificate_aux!=nullptr && BIO_read_ex(bio_certificate,certificate_aux, lenght,&writed) && lenght==writed)
						{
							Certificate_str=std::string{certificate_aux,writed};
						}
					}
				}
			}
			BIO_free_all(bio_certificate);
			bio_certificate=nullptr;
			delete []certificate_aux;
			certificate_aux=nullptr;
			X509_free(certificate);
			certificate=nullptr;
			ASN1_INTEGER_free(aserial);
			aserial=nullptr;
		}
	}
	BIO_free_all(bio_requisition);
	bio_requisition=nullptr;
	X509_REQ_free(requisition);
	requisition=nullptr;
	if(Certificate_str.size())
	{
		return Certificate_str;
	}
	throw std::runtime_error{"It was not possible generate the auto-signed digital certificate"};
}

