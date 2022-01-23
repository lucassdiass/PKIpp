/*
 * ecc.cpp
 *
 *  Created on: 11 de ago de 2020
 *      Author: Lucas Dias
 */
#include "PKI++.hpp"

#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
using namespace PKI;
PKIECC::PKIECC()  : InterfacePKI::SignatureDigital{},InterfacePKI::StreamStore{}
{
	EVP_PKEY * PairKey=nullptr;
	BIO*bp_public=nullptr,*bp_private=nullptr;
	int ret=1,round=0;
	EVP_PKEY_CTX * params = nullptr,*kctx=nullptr;
	params=EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
	EVP_PKEY * pbtx=nullptr;
	if(params==nullptr||params==NULL)
	{
		throw std::runtime_error{"Erro em instanciar chaves RSA"};
	}
	while(ret==1 && round<7)
	{
		switch(round)
		{
		case 0 :
		{
			ret=EVP_PKEY_paramgen_init(params);
			break;
		}
		case 1:
		{
			ret=EVP_PKEY_CTX_set_ec_paramgen_curve_nid(params, NID_secp256k1);
			break;
		}
		case 2:
		{
			pbtx=EVP_PKEY_new();
			if(pbtx==NULL||pbtx==nullptr)
			{
				ret=0;
			}
			break;
		}
		case 3 :
		{
			ret=EVP_PKEY_paramgen(params,&pbtx);
			break;
		}
		case 4:
		{
			if(pbtx!=NULL)
			{
				kctx = EVP_PKEY_CTX_new(pbtx, nullptr);
			}
			else
			{
				kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
			}
			if(kctx==nullptr || kctx==NULL)
			{
				ret=0;
			}

			break;
		}
		case 5:
		{
			ret=EVP_PKEY_keygen_init(kctx);
			break;
		}
		case 6:
		{
			ret=EVP_PKEY_keygen(kctx, &PairKey);
			break;
		}
		}
		round++;
	}
	EVP_PKEY_CTX_free(params);
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(pbtx);
	kctx=params=nullptr;
	pbtx=nullptr;
	if(ret!=1)
	{
		EVP_PKEY_free(PairKey);
		PairKey=nullptr;
		throw std::runtime_error{"Erro na geração de chaves"};
	}
	ret=0;
	bp_public=BIO_new(BIO_s_mem());
	bp_private=BIO_new(BIO_s_mem());
	//	PrvKey=EVP_PKEY_new();
	//	PubKey=EVP_PKEY_new();
	if(bp_private!=nullptr && bp_public!=nullptr )//&& PrvKey !=nullptr && PubKey!=nullptr)
	{
		if(PEM_write_bio_PUBKEY(bp_public,PairKey)>0 &&  PEM_write_bio_PrivateKey(bp_private,PairKey,nullptr, nullptr, 0, 0, nullptr)>0)
		{
			if((PubKey=PEM_read_bio_PUBKEY(bp_public,nullptr,nullptr,nullptr))!=nullptr &&
					(PrvKey=PEM_read_bio_PrivateKey(bp_private,nullptr,nullptr, nullptr))!=nullptr)
			{
				ret=1;
			}
		}
	}
	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	EVP_PKEY_free(PairKey);
	PairKey=nullptr;
	if(ret!=1)
	{
		EVP_PKEY_free(PubKey);
		EVP_PKEY_free(PrvKey);
		throw std::runtime_error{"Erro na geração de chaves"};
	}
}

PKIECC::PKIECC(std::string file_pub_path,bool isfile) : InterfacePKI::SignatureDigital{},InterfacePKI::StreamStore{}
{
	if(!file_pub_path.size())
	{
		throw std::runtime_error{"Caminho de arquivo inválido"};
	}
	int ret=1;
	BIO*bp_public=nullptr;
	std::ifstream fs{file_pub_path};
	if(isfile)
	{
		if(fs)
		{
			fs.close();
			bp_public=BIO_new(BIO_s_file());
			if((bp_public = BIO_new_file(file_pub_path.c_str(), "r+"))==nullptr
					|| (PubKey=PEM_read_bio_PUBKEY(bp_public,nullptr,nullptr,nullptr))==nullptr)
			{
				ret=0;
			}
		}
	}
	else
	{
		bp_public=BIO_new(BIO_s_mem());
		if(bp_public==nullptr || (BIO_write(bp_public,(void *)file_pub_path.c_str(),file_pub_path.size()))<0
				|| (PubKey=PEM_read_bio_PUBKEY(bp_public,nullptr,nullptr,nullptr))==nullptr)
		{
			ret=0;
		}
	}
	BIO_free_all(bp_public);
	bp_public=nullptr;
	if(!ret)
	{
		EVP_PKEY_free(PubKey);
		PubKey=nullptr;
		throw std::runtime_error{"Não foi possível carregar chave de "+file_pub_path};
	}
}
PKIECC::PKIECC(std::string file_pub_path, std::string file_prv_path, bool arefile) : PKIECC{file_pub_path,arefile}
{
	if(!file_prv_path.size())
	{
		throw std::runtime_error{"Caminho de arquivo inválido"};
	}
	int ret=1;
	BIO*bp_private=nullptr;
	std::ifstream fs{file_prv_path};
	if(arefile)
	{
		if(fs)
		{
			fs.close();
			bp_private=BIO_new(BIO_s_file());
			if((bp_private = BIO_new_file(file_prv_path.c_str(), "r+"))==nullptr
					|| (PrvKey=PEM_read_bio_PrivateKey(bp_private,nullptr,nullptr,nullptr))==nullptr)
			{
				ret=0;
			}
		}
	}
	else
	{
		bp_private=BIO_new(BIO_s_mem());
		if(bp_private==nullptr||BIO_write(bp_private,file_prv_path.c_str(),file_prv_path.size())<1
				|| (PrvKey=PEM_read_bio_PrivateKey(bp_private,nullptr,nullptr,nullptr))==nullptr )
		{
			ret=0;
		}
	}
	BIO_free_all(bp_private);
	if(!ret)
	{
		EVP_PKEY_free(PrvKey);
		throw std::runtime_error{"Não foi possível carregar chave de "+file_prv_path};
	}
}
std::string  PKIECC::SavePrvKey()
{
	BIO*bp_private = nullptr;
	std::string prvkeystr{};
	size_t  len=0, success=0;
	char *prvkeystr_aux=nullptr;
	bp_private=BIO_new(BIO_s_mem());
	if( bp_private!=nullptr && PEM_write_bio_PrivateKey(bp_private,PrvKey,nullptr, nullptr, 0, 0, nullptr)>0)
	{
		if(BIO_read_ex(bp_private,nullptr,-1,&len) && len>0)
		{
			prvkeystr_aux=new char[len];
			if(prvkeystr_aux!=nullptr)
			{
				if(BIO_read_ex(bp_private,(void*)prvkeystr_aux,len,&success)&&len==success)
				{
					for(int index=0;index<success;index++)
					{
						prvkeystr.push_back(*(prvkeystr_aux+index));
					}
				}
				delete []prvkeystr_aux;
				prvkeystr_aux=nullptr;
			}
		}
		BIO_free_all(bp_private);
		bp_private=nullptr;
	}
	if(!prvkeystr.size())
	{
		throw std::runtime_error{"Não foi possível salvar a chave privade em um String"};
	}
	return prvkeystr;
}
std::string  PKIECC::SavePubKey()
{
	BIO*bp_public = nullptr;
	std::string pubkeystr{};
	size_t  len=0, success=0;
	char *pubkeystr_aux=nullptr;
	bp_public=BIO_new(BIO_s_mem());
	if( bp_public!=nullptr &&PEM_write_bio_PUBKEY(bp_public,PubKey)>0)
	{
		if(BIO_read_ex(bp_public,nullptr,-1,&len) && len>0)
		{
			pubkeystr_aux=new char[len];
			if(pubkeystr_aux!=nullptr)
			{
				if(BIO_read_ex(bp_public,(void*)pubkeystr_aux,len,&success)&&len==success)
				{
					for(int index=0;index<success;index++)
					{
						pubkeystr.push_back(*(pubkeystr_aux+index));
					}
				}
				delete []pubkeystr_aux;
				pubkeystr_aux=nullptr;
			}
		}
		BIO_free_all(bp_public);
		bp_public=nullptr;
	}
	if(!pubkeystr.size())
	{
		throw std::runtime_error{"Não foi possível salvar a chave pública em um String"};
	}
	return pubkeystr;
}

void PKIECC::SetOtherPubKeyECDH(std::string OtherKey)
{
	BIO *bp_other=nullptr;
	bool WriteOk{false};
	EVP_PKEY *aux=nullptr;
	if(OtherKey.size())
	{
		bp_other=BIO_new(BIO_s_mem());

		if(bp_other!=nullptr && BIO_write(bp_other,OtherKey.data(),OtherKey.size()))
		{
			aux=PEM_read_bio_PUBKEY(bp_other,nullptr,nullptr,nullptr);
			WriteOk=(aux && EVP_PKEY_id(aux)==EVP_PKEY_EC);
			if(WriteOk)
			{
				if(OtherPub)
				{
					EVP_PKEY_free(OtherPub);
					OtherPub=nullptr;
				}
				OtherPub=aux;
				aux=nullptr;
			}
			else
			{
				EVP_PKEY_free(aux);
				aux=nullptr;
			}
			BIO_free(bp_other);
			bp_other=nullptr;
		}
	}
	if(!WriteOk)
	{
		throw std::runtime_error{"It is not possit set another public key"};
	}
}
void PKIECC::SavePubKey(std::string file_pub_path)
{
	BIO*bp_public = nullptr;
	if(!file_pub_path.size())
	{
		throw std::runtime_error{"Caminho de arquivo inválido"};
	}
	if((bp_public = BIO_new_file(file_pub_path.c_str(), "w+"))!=nullptr && PEM_write_bio_PUBKEY(bp_public,PubKey)>0)
	{
		BIO_free_all(bp_public);
		return;
	}
	std::runtime_error{"Não foi possível armazenar chave"};

}
void PKIECC::SavePrvKey(std::string file_prv_path)
{
	BIO*bp_private = nullptr;
	if(!file_prv_path.size())
	{
		throw std::runtime_error{"Caminho de arquivo inválido"};
	}
	if((bp_private = BIO_new_file(file_prv_path.c_str(), "w+"))!=nullptr && PEM_write_bio_PrivateKey(bp_private,PrvKey,NULL, NULL, 0, 0, NULL)>0)
	{
		BIO_free_all(bp_private);
		return;
	}
	std::runtime_error{"Não foi possível armazenar chave"};
}
std::string PKIECC::CalculateECDH()
{
	try
	{
		return GenerateSecret();
	}
	catch(...)
	{
		throw;
	}
}


std::string PKIECC::SignMessage(std::string message)
{
	size_t length=0;

	std::string signature{};
	unsigned char * signature_aux=nullptr;
	EVP_MD_CTX *mdctx = nullptr;

	mdctx = EVP_MD_CTX_create();
	if(mdctx != nullptr && EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr,this->PrvKey) &&
			EVP_DigestSignUpdate(mdctx, message.data(), message.size()) &&
			EVP_DigestSignFinal(mdctx,nullptr,&length)
	)
	{
		signature_aux=(unsigned char*)OPENSSL_malloc(sizeof(unsigned char) * (length));
		if(signature_aux!=nullptr && EVP_DigestSignFinal(mdctx, signature_aux, &length))
		{
			for(int index=0;index<length;index++)
			{
				signature.push_back(*(signature_aux+index));
			}
		}
	}
	EVP_MD_CTX_destroy(mdctx);
	OPENSSL_free(signature_aux);
	signature_aux=nullptr;
	if(!signature.size())
	{

		throw std::runtime_error{"Não foi possível assinar a mensagem "+message};
	}


	return signature;
}
bool PKIECC::VerifySignatureMessage(std::string message, std::string signature)
{
	EVP_MD_CTX *mdctx = nullptr;
	int ret=0;
	mdctx = EVP_MD_CTX_create();
	if(mdctx != nullptr)
	{
		if(EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr,this->PubKey))
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

std::string PKIECC::EncryptMessage(const std::string&plain)
{
	if(!plain.size())
	{
		throw std::runtime_error{"Texto inválido para cifragem"};
	}
	std::string encrypted{};
	int len=0,ciphertext_len=0;
	float len_aux=0;
	EVP_CIPHER_CTX *ctx=nullptr;
	unsigned char * encrypted_aux=nullptr;
	try
	{
		auto secret=GenerateSecret();
		if((ctx = EVP_CIPHER_CTX_new())!=nullptr)
		{
			if(EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, ( unsigned char *)secret.data(), nullptr)>0)
			{
				//	len=EVP_CIPHER_block_size(EVP_aes_256_ecb());
				len_aux=(float)plain.size()/(float)EVP_CIPHER_block_size(EVP_aes_256_ecb());
				//len=len*EVP_CIPHER_block_size(EVP_aes_256_ecb());
				len=len_aux;
				if(len_aux!=(float)len)
				{
					len=(len*EVP_CIPHER_block_size(EVP_aes_256_ecb()))  +    EVP_CIPHER_block_size(EVP_aes_256_ecb());
				}
				else
				{
					len=(len*EVP_CIPHER_block_size(EVP_aes_256_ecb()));
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
		std::runtime_error{"Não foi possível cifrar a mensagem"};
	}
	return encrypted;
}
std::string PKIECC::GenerateSecret()
{
	int ret=1,round=0;
	EVP_PKEY_CTX  *ctx=nullptr;
	unsigned char *secret=nullptr,*secret_aux=nullptr;
	std::string Key{};
	EVP_MD_CTX *mdctx=nullptr;
	size_t len=0;
	unsigned int digest_size=0;
	while(ret==1 &&round<11)
	{
		switch(round)
		{
		case 0:
			ctx=EVP_PKEY_CTX_new(this->PrvKey,nullptr);
			if(ctx==nullptr||ctx==NULL)
			{
				ret=0;
			}
			break;
		case 1:
			ret=EVP_PKEY_derive_init(ctx);
			break;
		case 2:
			if(OtherPub!=nullptr)
			{
				ret=EVP_PKEY_derive_set_peer(ctx,OtherPub);
			}
			else
			{
				ret=EVP_PKEY_derive_set_peer(ctx,PubKey);
			}
			break;
		case 3:
			ret=EVP_PKEY_derive(ctx,NULL,&len);
			break;
		case 4:
			secret_aux = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*len);
			if(secret_aux==NULL||secret_aux==nullptr)
			{
				ret=0;
			}
			break;
		case 5:
			ret=EVP_PKEY_derive(ctx, secret_aux, &len);
			break;
		case 6:
			mdctx = EVP_MD_CTX_new();
			if(mdctx==NULL||mdctx==nullptr)
			{
				ret=0;
			}
			break;
		case 7:
			ret=EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
			break;
		case 8:
			ret=EVP_DigestUpdate(mdctx, secret_aux, len);
			break;
		case 9:
			secret = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
			digest_size=EVP_MD_size(EVP_sha256());
			if(secret==NULL||secret==nullptr)
			{
				ret=0;
			}
			break;
		case 10:
			ret=EVP_DigestFinal_ex(mdctx, secret, &digest_size);
			break;
		}
		round++;
	}
	EVP_PKEY_CTX_free(ctx);
	EVP_MD_CTX_free(mdctx);
	OPENSSL_free(secret_aux);
	if(ret!=1)
	{
		OPENSSL_free(secret);
		secret=nullptr;
		throw std::runtime_error{"Não foi possível gerar segredo"};
	}
	for(int index=0;index<digest_size;index++)
	{
		Key.push_back(*(secret+index));
	}
	OPENSSL_free(secret);
	secret=nullptr;
	return Key;
}
std::string PKIECC::DecryptMessage(const std::string& encrypted)
{
	if(!encrypted.size())
	{
		throw std::runtime_error{"Texto inválido para decifragem"};
	}
	std::cout << "cypher len: "<<encrypted.size()<<"\n";
	std::string plain{};
	int len=0,plen=0;;

	EVP_CIPHER_CTX *ctx=nullptr;
	unsigned char * decrypted_aux=nullptr;
	try
	{
		auto secret=GenerateSecret();
		if((ctx = EVP_CIPHER_CTX_new())!=nullptr)
		{
			if(EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, ( unsigned char *)secret.data(), nullptr)>0)
			{
				len=0;//encrypted.size();//EVP_CIPHER_block_size(EVP_aes_256_ecb());
				decrypted_aux=(unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*(1+encrypted.size()) );
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
		std::runtime_error{"Não foi possível cifrar a mensagem"};
	}
	return plain;
}

std::string PKIECC::GenerateRequest(const request_data & dados)
{
	X509_REQ *x509_req=nullptr;
	BIO * out_request=nullptr;
	std::string request_str{};
	char *request_aux=nullptr;
	size_t len=0,success=0;
	bool condition=false;
	X509_NAME * x509_name=nullptr;
	if((x509_req=X509_REQ_new()) !=nullptr && (x509_name=X509_REQ_get_subject_name(x509_req))!=nullptr)
	{
		if(dados.szCountry.size() && dados.szProvince.size() && dados.szCity.size()&&dados.szOrganization.size()&&dados.szCommon.size() )
		{
			//int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type, const unsigned char *bytes, int len, int loc, int set);
			condition=	X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, ( const unsigned char *) dados.szCountry.c_str(),-1,-1,0) &&
					X509_NAME_add_entry_by_txt(x509_name,"ST",MBSTRING_ASC,(const unsigned char*)dados.szProvince.c_str(),-1,-1,0) &&
					X509_NAME_add_entry_by_txt(x509_name,"L",MBSTRING_ASC,(const unsigned char*)dados.szCity.c_str(),-1,-1,0) &&
					X509_NAME_add_entry_by_txt(x509_name,"O",MBSTRING_ASC,(const unsigned char*)dados.szOrganization.c_str(),-1,-1,0) &&
					X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC,(const unsigned char*)dados.szCommon.c_str(),-1,-1,0) &&
					X509_REQ_set_pubkey(x509_req,PubKey) &&
					X509_REQ_sign(x509_req,PrvKey,EVP_sha256());
			if(condition && (out_request=BIO_new(BIO_s_mem()))!=nullptr && PEM_write_bio_X509_REQ(out_request,x509_req)
			&&	BIO_read_ex(out_request,nullptr,-1,&len) && len>0)
			{
				request_aux=new char[len];
				if(request_aux!=nullptr && BIO_read_ex(out_request, (void*)request_aux, len,&success) && success==len)
				{
					request_str=std::string{request_aux,len};
				}
			}
		}
	}
	//OPENSSL_free(x509_name);
	X509_REQ_free(x509_req);
	BIO_free_all(out_request);
	delete[]request_aux;
	if(!request_str.size())
	{
		throw std::runtime_error{"Não foi possível gerar requisição"};
	}
	return request_str;
}
std::string PKIECC::SelfSign(std::string request)
{
	X509_REQ *requisition=nullptr;
	std::string Certificado{};
	char *certificado_aux=nullptr;
	X509 *certificate=nullptr;
	ASN1_INTEGER *aserial=nullptr;
	size_t tamanho=0, escritos=0;
	BIO * bio_requisition=nullptr,* bio_certificate=nullptr;
	if( (bio_requisition=BIO_new(BIO_s_mem()))!=nullptr && 	BIO_write(bio_requisition, request.data(), request.size()) &&
			(requisition=PEM_read_bio_X509_REQ(bio_requisition,nullptr,nullptr,nullptr))!=nullptr )
	{
		if(X509_REQ_verify(requisition,this->PubKey))
		{
			certificate=X509_new();
			aserial=ASN1_INTEGER_new();
			if(certificate!=nullptr && X509_set_version(certificate,2) && aserial!=nullptr && ASN1_INTEGER_set(aserial,1) &&
					X509_set_subject_name(certificate,X509_REQ_get_subject_name(requisition)) &&
					X509_set_issuer_name(certificate,X509_REQ_get_subject_name(requisition)) &&
					X509_set_pubkey(certificate,this->PubKey) &&
					X509_gmtime_adj(X509_get_notBefore(certificate),0)&&
					X509_gmtime_adj(X509_get_notAfter(certificate),365*3*24*60*60)&&
					this->PrvKey!=nullptr &&
					X509_sign(certificate,this->PrvKey, EVP_sha256()))
			{
				bio_certificate=BIO_new(BIO_s_mem());
				if(bio_certificate!=nullptr && PEM_write_bio_X509(bio_certificate,certificate))
				{
					if(BIO_read_ex(bio_certificate,nullptr,-1,&tamanho) && tamanho)
					{
						certificado_aux=new char[tamanho];
						if(certificado_aux!=nullptr && BIO_read_ex(bio_certificate,certificado_aux,tamanho,&escritos) && tamanho==escritos)
						{
							Certificado=std::string{certificado_aux,escritos};
						}
					}
				}
			}
		}
	}
	BIO_free_all(bio_requisition);
	bio_requisition=nullptr;
	X509_REQ_free(requisition);
	requisition=nullptr;
	BIO_free_all(bio_certificate);
	bio_certificate=nullptr;
	delete []certificado_aux;
	certificado_aux=nullptr;
	X509_free(certificate);
	certificate=nullptr;
	ASN1_INTEGER_free(aserial);
	aserial=nullptr;
	if(Certificado.size())
	{
		return Certificado;
	}
	throw std::runtime_error{"Não foi possível gerar certificado auto-assinador"};
}

PKIECC::~PKIECC()
{
	EVP_PKEY_free(PrvKey);
	//O
	PrvKey=nullptr;
	EVP_PKEY_free(PubKey);
	PubKey=nullptr;
}
