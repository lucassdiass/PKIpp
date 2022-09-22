/*
 * Certificate.cpp
 *
 *  Created on: 24 de ago de 2020
 *      Author: Lucas Dias
 */
#include "PKI++.hpp"
#include <iostream>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/asn1.h>
#include <ctime>       /* time_t, struct tm, difftime, time, mktime */
using namespace PKI;
PKICertificate::PKICertificate(std::string file_cert_path,std::string crlpath, bool isfile)//:CrlPath{crlpath}
{
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	EVP_PKEY *pkey = nullptr;
	BIO *x509_bio=nullptr, *crlbio=nullptr;
	if(isfile)
	{
		x509_bio=BIO_new_file(file_cert_path.c_str(),"r+");
		crlbio=BIO_new_file(crlpath.c_str(),"r+");
		Cert=X509_new();
		if(x509_bio!=nullptr && Cert!=nullptr  && BIO_read_filename(x509_bio,file_cert_path.c_str()) && PEM_read_bio_X509(x509_bio,&Cert,nullptr,nullptr) )
		{
			pkey=X509_get_pubkey(Cert);
		}
		if(crlbio)
		{
			Crl=PEM_read_bio_X509_CRL(crlbio, nullptr, nullptr, nullptr);
		}
	}
	else
	{
		Cert=X509_new();
		x509_bio=BIO_new(BIO_s_mem());
		crlbio=BIO_new(BIO_s_mem());
		if(x509_bio!=nullptr && BIO_write(x509_bio,(void *)file_cert_path.c_str(),file_cert_path.size()) && Cert!=nullptr && PEM_read_bio_X509(x509_bio,&Cert,nullptr,nullptr))
		{
			pkey=X509_get_pubkey(Cert);
		}
		if(crlbio && !BIO_write(crlbio,(void *)crlpath.c_str(),crlpath.size()))
		{
			BIO_free_all(crlbio);
			crlbio=nullptr;
		}
	}
	if(crlbio)
	{
		Crl=PEM_read_bio_X509_CRL(crlbio, nullptr, nullptr, nullptr);
		BIO_free_all(crlbio);
		crlbio=nullptr;
	}

	BIO_free_all(x509_bio);
	x509_bio=nullptr;
	if(pkey!=nullptr)
	{
		switch(EVP_PKEY_id(pkey))
		{
		case EVP_PKEY_RSA:
		{
			this->Type=TypeAlgorithm::rsa;
			this->Rsa=new PKI::PKIRSA{this->PubKeyToStr(pkey),false};
			break;
		}
		case EVP_PKEY_EC:
			this->Type=TypeAlgorithm::ecc;
			this->Ecc=new PKI::PKIECC{this->PubKeyToStr(pkey),false};
			break;
		default:
			EVP_PKEY_free(pkey);
			throw std::runtime_error{"Unsupported algorithm"};
		}
	}
	EVP_PKEY_free(pkey);
	pkey=nullptr;
}

PKICertificate::PKICertificate(std::string file_path , std::string file_prv,std::string crlpath,bool arefiles) : PKICertificate{file_path,crlpath,arefiles }
{
	BIO *prvbio=nullptr;
	std::string certaux{};
	std::ifstream if_prv{file_prv};
	EVP_PKEY *prv=nullptr;
	if(arefiles)
	{
		if_prv.close();
		prvbio=BIO_new_file(file_prv.c_str(), "r+");
		if(prvbio!=nullptr)
		{
			prv=PEM_read_bio_PrivateKey(prvbio,nullptr,nullptr,nullptr);
		}
	}
	else
	{
		prvbio=BIO_new(BIO_s_mem());
		if(prvbio!=nullptr && BIO_write(prvbio,file_prv.c_str(),file_prv.size()))
		{
			prv=PEM_read_bio_PrivateKey(prvbio,nullptr,nullptr,nullptr);
		}
	}
	BIO_free_all(prvbio);
	prvbio=nullptr;
	switch(this->Type)
	{
	case TypeAlgorithm::ecc :
		this->Ecc->PrvKey=prv;
		break;
	case TypeAlgorithm::rsa:
		this->Rsa->PrvKey=EVP_PKEY_ptr(prv, EVP_PKEY_free);
		break;
	default:
		throw std::runtime_error{"Unsupported algorithm"};
	}
}

std::string PKICertificate::SignMessage(std::string message)
{
	try
	{
		switch (this->Type)
		{
		case TypeAlgorithm::ecc :
			return Ecc->SignMessage(message);
		case TypeAlgorithm::rsa :
			return Rsa->SignMessage(message);
		default :
			throw std::runtime_error{"Unsupported algorithm"};
		}
	}
	catch(...)
	{
		throw;
	}
}
bool PKICertificate::VerifySignatureMessage(std::string text, std::string signature)
{
	try
	{
		switch (this->Type)
		{
		case TypeAlgorithm::ecc :
			return Ecc->VerifySignatureMessage(text,signature);
		case TypeAlgorithm::rsa :
			return Rsa->VerifySignatureMessage(text,signature);
		default :
			throw std::runtime_error{"Unsupported algorithm"};
		}
	}
	catch(...)
	{
		throw;
	}
}

std::string PKICertificate::EncryptMessage(const std::string& plain)
{
	try
	{
		switch (this->Type)
		{
		case TypeAlgorithm::ecc :
			return Ecc->EncryptMessage(plain);
		case TypeAlgorithm::rsa :
			return Rsa->EncryptMessage(plain);
		default :
			throw std::runtime_error{"Unsupported algorithm"};
		}
	}
	catch(...)
	{
		throw;
	}
}

std::string PKICertificate::DecryptMessage(const std::string&encrypted)
{
	try
	{
		switch (this->Type)
		{
		case TypeAlgorithm::ecc :
			return Ecc->DecryptMessage(encrypted);
		case TypeAlgorithm::rsa :
			return Rsa->DecryptMessage(encrypted);
		default :
			throw std::runtime_error{"Unsupported algorithm"};
		}
	}
	catch(...)
	{
		throw;
	}
}
bool
PKICertificate::VerifySubjectName(std::string address )
{
	if(Cert)
	{
		return X509_check_host(Cert, address.data(), address.size(),0,nullptr) ||
				X509_check_ip(Cert, (unsigned char*)address.data(), address.size(),0)||
				X509_check_ip_asc(Cert, address.data(),0);
	}
	return false;
}
std::string
PKICertificate::GetSerial()
{
	std::string serial;
	if(Cert)
	{
		auto nserial=X509_get0_serialNumber(Cert);
		if(nserial && nserial->length)
		{
			serial=std::string{reinterpret_cast<char *>(nserial->data), static_cast<size_t>(nserial->length)};
		}
	}
	return serial;
}
std::string  PKICertificate::PubKeyToStr(EVP_PKEY*publickey)
{
	std::string pubkey_str{};
	char *pubkey=nullptr;
	size_t len=0, success=0;
	BIO*bio_public=nullptr;
	bio_public=BIO_new(BIO_s_mem());
	if(bio_public!=nullptr)
	{
		if(PEM_write_bio_PUBKEY(bio_public,publickey) && BIO_read_ex(bio_public,nullptr,-1,&len) && len)
		{
			pubkey=new char[len];
			if(pubkey!=nullptr && BIO_read_ex(bio_public,(void *)pubkey,len,&success) )
			{
				for(int index=0;index<success;index++)
				{
					pubkey_str.push_back(*(pubkey+index));
				}
			}
		}
	}
	delete[]pubkey;
	pubkey=nullptr;
	BIO_free_all(bio_public);
	return pubkey_str;
}
std::string PKICertificate::CertToStr(X509 * certificate)
{
	BIO*bio_certificate=nullptr;
	std::string certificate_str{};
	char*certificate_aux=nullptr;
	size_t len=0,success=0;
	if(certificate!=nullptr)
	{
		bio_certificate=BIO_new(BIO_s_mem());
		if(bio_certificate!=nullptr && PEM_write_bio_X509(bio_certificate,certificate) && BIO_read_ex(bio_certificate,nullptr,-1,&len) && len)
		{
			certificate_aux=new char[len];
			if(certificate_aux!=nullptr && BIO_read_ex(bio_certificate,(void*)certificate_aux,len,&success))
			{
				for(int index=0;index<success;index++)
				{
					certificate_str.push_back(*(certificate_aux+index));
				}
			}
		}
	}
	delete[]certificate_aux;
	BIO_free_all(bio_certificate);
	return certificate_str;
}
bool PKICertificate::VerifySignatureCert(const std::string certificate_stream, bool isfile)
{
	BIO*bio_certificate=nullptr;
	X509*certificate=nullptr;
	bool canwritecert=false,verification=false;
	EVP_PKEY * pubcert=nullptr;
	if(isfile)
	{
		bio_certificate=BIO_new_file(certificate_stream.data(),"r+");
		canwritecert=(bio_certificate!=nullptr);
	}
	else
	{
		bio_certificate=BIO_new(BIO_s_mem());
		canwritecert=(bio_certificate!=nullptr && BIO_write(bio_certificate,(void*)certificate_stream.c_str(),certificate_stream.size()));
	}
	if(canwritecert)
	{
		certificate= PEM_read_bio_X509(bio_certificate,nullptr,nullptr,nullptr);
		pubcert=X509_get_pubkey(Cert);
		if(certificate!=nullptr && pubcert!=nullptr)
		{
			verification=X509_verify(certificate,pubcert)>0 && this->VerifyValidDataOk(certificate) && !VerifyCRLOk(certificate);
		}
	}
	BIO_free_all(bio_certificate);
	bio_certificate=nullptr;
	X509_free(certificate);
	certificate=nullptr;
	EVP_PKEY_free(pubcert);
	pubcert=nullptr;
	return verification;
}
std::string PKICertificate::SignCert(const struct Requisition&requisicao, int serial, std::vector<std::string> extensions )
{
	BIO*bio_request=nullptr;
	X509_REQ * requisition=nullptr;
	X509*certificate=nullptr;
	std::string certificate_str{},extensionsstr{};
	ASN1_INTEGER *aserial=nullptr;
	bool ok=false,signok=false;
	X509V3_CTX ctx;
	X509_EXTENSION *ex = nullptr;
	EVP_PKEY * pub=nullptr;
	if(requisicao.RequisitionContent.size())
	{
		if(requisicao.IsFile)
		{
			bio_request=BIO_new(BIO_s_file());
			ok=(bio_request!=nullptr && BIO_read_filename(bio_request,requisicao.RequisitionContent.c_str()) &&
					(requisition=PEM_read_bio_X509_REQ(bio_request,nullptr,nullptr,nullptr)) !=nullptr);
		}
		else
		{
			bio_request=BIO_new(BIO_s_mem());
			ok=(bio_request!=nullptr && BIO_write(bio_request,(void*)requisicao.RequisitionContent.data(),requisicao.RequisitionContent.size())
			&& (requisition=PEM_read_bio_X509_REQ(bio_request,nullptr,nullptr,nullptr)) !=nullptr);
		}
		if(ok)
		{
			ok=false;
			certificate=X509_new();
			//Version number is decremented. For exemple,X509v3 is version number 3-1=2;
			if(certificate!=nullptr && X509_set_version(certificate,2))
			{
				std::srand(std::time(nullptr));
				serial=serial ? serial : std::rand();
				aserial=ASN1_INTEGER_new();
				if(aserial!=nullptr && ASN1_INTEGER_set(aserial,serial)&&X509_set_serialNumber(certificate,aserial) &&
						X509_set_subject_name(certificate,X509_REQ_get_subject_name(requisition)) &&
						X509_set_issuer_name(certificate,X509_get_subject_name(Cert)) )
				{

					if((pub=X509_REQ_get_pubkey(requisition))!=nullptr && X509_REQ_verify(requisition,pub ))
					{

						if(X509_set_pubkey(certificate,pub)&&
								X509_gmtime_adj(X509_get_notBefore(certificate),0)&&
								X509_gmtime_adj(X509_get_notAfter(certificate),365*3*24*60*60)
						)
						{
							if(extensions.size())
							{
								X509V3_set_ctx_nodb(&ctx);
								X509V3_set_ctx(&ctx, Cert, certificate, nullptr, nullptr, 0);
								extensionsstr=extensions[0];
								for(unsigned int index=1;index<extensions.size();index++)
								{
									extensionsstr.push_back(',');
									extensionsstr+=extensions[index];
								}
								ex=X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, extensionsstr.data());
								if(ex==nullptr)
								{
									throw std::runtime_error{"It was not possible add extensions "+extensionsstr};
								}
								bool adexter=X509_add_ext(certificate, ex, -1);
								X509_EXTENSION_free(ex);
								ex=nullptr;
								if(!adexter)
								{
									throw std::runtime_error{"It was not possible add extensions "+extensionsstr};
								}
							}
							else
							{
								X509V3_set_ctx(&ctx, Cert, certificate, nullptr, nullptr, 0);

							}
							switch (Type)
							{
							case TypeAlgorithm::rsa :
								signok=this->Rsa->PrvKey.get()==nullptr ? false : X509_sign(certificate,this->Rsa->PrvKey.get(),EVP_sha256());
								break;
							case TypeAlgorithm::ecc:
								signok=this->Ecc->PrvKey==nullptr ? false : X509_sign(certificate,this->Ecc->PrvKey,EVP_sha256());
								break;
							default :
								signok=false;
								break;
							}
						}
					}
				}
				if(signok)
				{
					certificate_str=this->CertToStr(certificate);
				}
			}
		}
		BIO_free_all(bio_request);
		X509_REQ_free(requisition);
		ASN1_INTEGER_free(aserial);
		EVP_PKEY_free(pub);
	}
	X509_free(certificate);
	if(certificate_str.size())
	{
		return certificate_str;
	}
	throw std::runtime_error{"It was not possible sign the certificate"};
}
bool PKICertificate::VerifyValidDataOk(X509 *certificate)
{
	if(certificate!=nullptr && certificate!=NULL)
	{
		//when time_t * is nullptr or NULL, the hout from the system is used
		return  (X509_cmp_time(X509_get_notBefore(certificate), nullptr)==-1) && (X509_cmp_time(X509_get_notAfter(certificate), nullptr));
	}
	return false;
}

bool PKICertificate::isExpired()
{

	ASN1_TIME* time_cert=nullptr;//X509_get_notAfter(this->Cert);
	struct tm t;
	time_t atual;
	if(Cert!=nullptr &&(time_cert=X509_get_notAfter(this->Cert))!=nullptr)
	{
		atual=std::time(nullptr);
		const char* str = (const char*) time_cert->data;
		size_t i = 0;

		memset(&t, 0, sizeof(t));

		if (time_cert->type == V_ASN1_UTCTIME) /* two digit year */
		{
			t.tm_year = (str[i++] - '0') * 10 + (str[i++] - '0');
			if (t.tm_year < 70)
				t.tm_year += 100;
		}
		else if (time_cert->type == V_ASN1_GENERALIZEDTIME) /* four digit year */
		{
			t.tm_year = (str[i++] - '0') * 1000 + (str[i++] - '0') * 100 + (str[i++] - '0') * 10 + (str[i++] - '0');
			t.tm_year -= 1900;
		}
		t.tm_mon = ((str[i++] - '0') * 10 + (str[i++] - '0')) - 1; // -1 since January is 0 not 1.
		t.tm_mday = (str[i++] - '0') * 10 + (str[i++] - '0');
		t.tm_hour = (str[i++] - '0') * 10 + (str[i++] - '0');
		t.tm_min  = (str[i++] - '0') * 10 + (str[i++] - '0');
		t.tm_sec  = (str[i++] - '0') * 10 + (str[i++] - '0');

		/* Note: we did not adjust the time based on time zone information */
		auto seconds=std::difftime(atual,mktime(&t));
		if(seconds<(60*60*24*30))//30 dias
		{
			return true;
		}
	}
	return false;
}
bool PKICertificate::VerifyOwnCRL()
{
	EVP_PKEY * pk=nullptr;
	bool ok=false;
	if(!Crl)
	{
		throw std::runtime_error{"Crl is null!"};
	}
	switch (Type)
	{
	case TypeAlgorithm::ecc :
		pk=this->Ecc->PubKey;
		break;
	case TypeAlgorithm::rsa :
		pk=this->Rsa->PubKey.get();
		break;
	default :
		pk=nullptr;
	}
	if(Cert&&pk)
	{
		ok=X509_CRL_verify(Crl,pk )==1;
	}
	return ok;
}
bool PKICertificate::VerifyCRLOk(X509 *certificate)
{
	bool ok=false;
	X509_REVOKED *ret=nullptr;
	EVP_PKEY*pk=nullptr;
	if(Crl!=nullptr && Cert!=nullptr)
	{
		pk=X509_get_pubkey(Cert);
		if( pk && X509_CRL_verify(Crl,pk)==1 && certificate)
		{
			ok=(X509_CRL_get0_by_cert(Crl,&ret,certificate)==1);
		}
		EVP_PKEY_free(pk);
		pk=nullptr;
	}
	return ok;
}

//bool VerifyValidData(X509 *);
PKICertificate&PKICertificate::CreateCRL(std::string CRLfile)
{
	bool ok=false;
	X509_CRL *crl=nullptr;
	BIO*biooutput=nullptr;
	crl=X509_CRL_new();
	EVP_PKEY*skkey=nullptr;
	time_t t=time(nullptr);
	ASN1_TIME *tm =nullptr;
	switch (Type)
	{
	case TypeAlgorithm::ecc :
		skkey=this->Ecc->PrvKey;
		break;
	case TypeAlgorithm::rsa :
		skkey=this->Rsa->PrvKey.get();
		break;
	default:
		skkey = nullptr;
	}
	biooutput=BIO_new_file(CRLfile.c_str(),"w");
	ok=(crl!=nullptr && skkey!=nullptr && (tm=ASN1_TIME_set(nullptr,t))!=nullptr && X509_CRL_set1_lastUpdate(crl,tm) &&
			X509_CRL_set_version(crl,2) &&
			X509_CRL_set_issuer_name(crl,X509_get_subject_name(Cert)) &&
			X509_CRL_sign(crl,skkey,EVP_sha256()) &&
			biooutput!=nullptr && PEM_write_bio_X509_CRL(biooutput,crl)>0);
	BIO_free_all(biooutput); biooutput=nullptr;

	X509_CRL_free(crl); crl=nullptr;
	if(!ok)
	{
		throw std::runtime_error{"It was not possible create CRL"};
	}
	return *this;
}
PKICertificate&PKICertificate::RevokeCert(std::string cert,bool isfile)
{
	X509*certificate=nullptr;
	X509_REVOKED *x=nullptr;
	time_t t=time(nullptr);
	ASN1_INTEGER *serial=nullptr;
	BIO *io=nullptr,*ocrl=nullptr;
	ASN1_TIME *tm =nullptr;// ASN1_TIME_new();
	EVP_PKEY*skkey=nullptr,*pkey=nullptr;
	bool ok=true;
	if(Crl)
	{
		switch (Type)
		{
		case TypeAlgorithm::ecc :
			skkey=this->Ecc->PrvKey;
			pkey=this->Ecc->PubKey;
			break;
		case TypeAlgorithm::rsa :
			skkey=this->Rsa->PrvKey.get();
			pkey=this->Rsa->PubKey.get();
			break;
		default :
			skkey=nullptr;
			pkey=nullptr;
		}
		if(isfile)
		{
			if((io=BIO_new_file(cert.c_str(),"r+"))!=nullptr &&
					(certificate=PEM_read_bio_X509(io,nullptr,nullptr,nullptr))!=nullptr)
			{
				serial=X509_get_serialNumber(certificate);
			}
		}
		else
		{
			io=BIO_new(BIO_s_mem());
			if(io!=nullptr &&
					(certificate=PEM_read_bio_X509(io,nullptr,nullptr,nullptr))!=nullptr)
			{
				serial=X509_get_serialNumber(certificate);
			}
		}


		if(pkey!=nullptr && Crl!=nullptr &&  X509_CRL_verify(Crl,pkey)<=0)
		{
			X509_CRL_free(Crl);Crl=nullptr;

			pkey=nullptr;
		}

		if(Crl==nullptr)
		{
			Crl=X509_CRL_new();
		}

		ok=(X509_verify(certificate,X509_get_pubkey(this->Cert))<=0 || !this->VerifyValidDataOk(certificate)|| serial==nullptr || (tm=ASN1_TIME_set(nullptr,t))==nullptr || Crl==nullptr ||
				(x=X509_REVOKED_new())==nullptr ||
				X509_REVOKED_set_serialNumber(x,serial)<=0 ||
				X509_REVOKED_set_revocationDate(x,tm)<=0 ||
				!X509_CRL_add0_revoked(Crl,x) ||
				!X509_CRL_set1_nextUpdate(Crl,tm) ||
				!X509_CRL_set_version(Crl,2) ||
				!X509_CRL_set_issuer_name(Crl,X509_get_subject_name(Cert)) ||
				!X509_CRL_sign(Crl,skkey,EVP_sha256()) || ocrl==nullptr ||
				!PEM_write_bio_X509_CRL(ocrl,Crl));
	}
	BIO_free_all(io);io=nullptr;
	BIO_free_all(ocrl);ocrl=nullptr;
	ASN1_TIME_free(tm);tm=nullptr;
	X509_REVOKED_free(x); x=nullptr;
	skkey=nullptr;

	if(ok)
	{
		throw std::runtime_error{"It was not possible sign and revogate the digital certificate"};
	}
	return *this;
}
void  PKICertificate::SaveCRL(std::string crlpath)
{
	BIO*bp_crl = nullptr;
	if(!crlpath.size())
	{
		throw std::runtime_error{"Invalid path"};
	}
	if((bp_crl = BIO_new_file(crlpath.c_str(), "w+"))!=nullptr && PEM_write_bio_X509_CRL(bp_crl,Crl)>0)
	{
		BIO_free_all(bp_crl);
		bp_crl=nullptr;
		return;
	}
	BIO_free_all(bp_crl);
	bp_crl=nullptr;
	throw std::runtime_error{"It was not possible store CRL."};
}
std::string PKICertificate::SavePubKey()
{
	std::string None{};
	BIO*bp_public = nullptr;
	std::string pubkeystr{};
	size_t  len=0, success=0;
	char *pubkeystr_aux=nullptr;
	bp_public=BIO_new(BIO_s_mem());
	if(Cert!=nullptr&& bp_public!=nullptr &&PEM_write_bio_X509(bp_public,Cert)>0)
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
		return None;
	}
	return pubkeystr;
}
void PKICertificate::UpdateCrl(std::string crl, bool isfile)
{
	X509_CRL *tmpcrl=nullptr;
	EVP_PKEY *pkey=nullptr;
	BIO*bioncrl=nullptr;
	if(crl.size())
	{
		switch (Type)
		{
		case TypeAlgorithm::ecc :
			pkey=this->Ecc->PubKey;
			break;
		case TypeAlgorithm::rsa :
			pkey=this->Rsa->PubKey.get();
			break;
		default :
			pkey=nullptr;
		}
		if(isfile)
		{
			bioncrl=BIO_new_file(crl.c_str(),"r+");
		}
		else
		{
			bioncrl=BIO_new(BIO_s_mem());
			if(bioncrl && !BIO_write(bioncrl,(void *)crl.c_str(),crl.size()))
			{
				BIO_free_all(bioncrl);
				bioncrl=nullptr;
				pkey=nullptr;
			}
		}
		if(bioncrl)
		{
			tmpcrl=PEM_read_bio_X509_CRL(bioncrl, nullptr, nullptr, nullptr);
		}
		if(tmpcrl && pkey &&  X509_CRL_verify(tmpcrl,pkey))
		{
			X509_CRL_free(Crl);
			Crl=tmpcrl;
		}
		BIO_free_all(bioncrl);
		bioncrl=nullptr;
		pkey=nullptr;
	}
}
std::string PKICertificate::SavePrvKey()
{
	std::string None{};
	try
	{
		switch(Type)
		{
		case rsa:
			if(Rsa!=nullptr)
			{
				return Rsa->SavePrvKey();
			}
			break;
		case ecc:
			if(Ecc!=nullptr)
			{
				return Ecc->SavePrvKey();
			}
			break;
		default:
			return None;
		}
	}
	catch(...)
	{
		throw;
	}
	return None;
}

void PKICertificate::SavePrvKey(std::string pathfile)
{
	try
	{
		switch(Type)
		{
		case rsa:
			if(Rsa!=nullptr)
			{
				Rsa->SavePrvKey(pathfile);
			}
			break;
		case ecc:
			if(Ecc!=nullptr)
			{
				Ecc->SavePrvKey(pathfile);
			}
			break;
		default:
			return;
		}
	}
	catch(...)
	{
		throw;
	}
}

void PKICertificate::SavePubKey(std::string pathfile)
{
	try
	{
		bool ok=false;
		BIO*bp_public = nullptr;
		if(this->Cert==nullptr)
		{
			throw std::runtime_error{"Public Key is null"};
		}
		if(!pathfile.size())
		{
			throw std::runtime_error{"Invalid file path"};
		}
		ok=((bp_public = BIO_new_file(pathfile.c_str(), "w+"))!=nullptr && PEM_write_bio_X509(bp_public,this->Cert)>0);
		BIO_free_all(bp_public);
		bp_public=nullptr;
		if(!ok)
		{
			throw std::runtime_error{"It was not possible store the public key"};
		}
	}
	catch(...)
	{
		throw;
	}
}
PKICertificate::~PKICertificate()
{
	switch (Type)
	{
	case TypeAlgorithm::ecc :
		delete Ecc;
		Ecc=nullptr;
		break;
	case TypeAlgorithm::rsa :
		delete Rsa;
		Rsa=nullptr;
		break;
	default :
		break;
	}
	X509_free(Cert);
	Cert=nullptr;
	X509_CRL_free(Crl);
	Crl=nullptr;
}
