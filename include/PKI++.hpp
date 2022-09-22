/*
 * PKI++.hpp
 *
 *  Created on: 7 de ago de 2020
 *      Author: Lucas Dias
 */

#ifndef PKI___HPP_
#define PKI___HPP_
#include "Interface.hpp"
#include "PKIppTypes.hpp"

namespace PKI
{
class PKICertificate;

enum TypeAlgorithm
{
	ecc,rsa,not_found
};

struct Requisition
{
	std::string RequisitionContent;
	bool IsFile;
};
typedef struct request_data
{
	std::string szCountry;
	std::string szProvince;
	std::string szCity;
	std::string szOrganization;
	std::string szCommon;
}	request_data;
std::istream&operator>>(std::istream&, request_data&);

class PKIRSA : public InterfacePKI::SignatureDigital, public InterfacePKI::Confidentiality, public InterfacePKI::StreamStore
{
public :
	friend class  PKICertificate;
	/*
	 * @brief Constructor that generate RSA pair key
	 * @param RSA key pair length. However, it needs greater equal to 3072.
	 */
	PKIRSA(unsigned int);
	/*
	 * @brief Construct that receive an RSA public key generate previously
	 * @param RSA public key. It can be string or file path.
	 * @param bool - true if param is file
	 */
	PKIRSA(std::string file_pub_path,bool isfile);
	/*
	 * @brief: Construct that receive an RSA public key generate previously
	 * @param: RSA public key. It can be content stored in a string or file path.
	 * @param: RSA private key. It can be content stored in a string or file path.
	 * @return: Bool - true if param is file
	 */
	PKIRSA(std::string file_pub_path, std::string file_prv_path,bool arefile);
	/*
	 * @brief: Make digital signature from a message receive as param.
	 * However, it can be throw std::runtime_error if RSA private key is nullptr,
	 * message has length equal to 0 or signature failed
	 * @param: Message to be signed
	 * @return: Signature's string
	 */
	std::string SignMessage(std::string ) override final;
	/*
	 * @brief: Check the signature and a text plan
	 * @param: text to be verified
	 * @param: text's signature
	 * @return: True if signature is ok, false, otherwise.
	 */
	bool VerifySignatureMessage(std::string text, std::string signature) override final;
	/*
	 *@brief: Method to encryption a message receive as param
	 *@param: message to be encrypted. Throw std::runtime_error if message is empty
	 *@return: Return a message encrypted
	 */
	std::string EncryptMessage(const std::string&) override final;
	/*
	 * @brief: Method to decrypt a encrypted text
	 * @param: message to be decrypted. Throw a exception std::runtime_error if message is empty or private key is nullptr
	 * @return:  Return a plain text
	 */
	std::string DecryptMessage(const std::string&) override final;
	/*
	 * @brief: Store RSA Public Key in a file
	 * @param: File path to store RSA Public Key
	 * @return:
	 */
	void SavePubKey(std::string ) override final;
	/*
	 * @brief: Store RSA Private Key in a file
	 * @param: File path to store RSA Private Key
	 * @return:
	 */
	void SavePrvKey(std::string ) override final;
	/*
	 * @brief: Store RSA Public Key in a string
	 * @param:
	 * @return: Return a RSA Public Key in a string with PEM format
	 */
	std::string SavePubKey() override final;
	/*
	 * @brief: Store RSA Private Key in a string
	 * @param:
	 * @return: Return a RSA Private Key in a string with PEM format
	 */
	std::string SavePrvKey() override final;
	/*
	 * @brief: Method to generate a certificate requisition in a PEM format
	 * @param: request_data is a data structure that stores a client information
	 * @return: Certificate's requisition in a string with PEM format
	 */
	std::string GenerateRequest(const request_data&);
	/*
	 * @brief: Method to generate a certificate self signed and return it in a string
	 * @param: Certificate requistion's string in PEM format
	 * @return: Certificate's string in PEM format
	 */
	std::string SelfSign(std::string);

	PKIRSA(const PKIRSA&)=default;


	PKIRSA&operator=(const PKIRSA&)=default;
	PKIRSA() = default;
	~PKIRSA() = default;
private :
	EVP_PKEY_ptr PubKey, PrvKey;
	//X509_ptr Cert;
	bool IsCert=false;
};

class PKIECC : public  InterfacePKI::SignatureDigital, InterfacePKI::Confidentiality, InterfacePKI::StreamStore
{
public :
	friend class  PKICertificate;
	PKIECC();
	/*
	 * @brief Construct that receive an ECC public key generate previously
	 * @param ECC public key. It can be string or file path.
	 * @param bool - true if param is file
	 */
	PKIECC(std::string file_pub_path, bool isfile);
	/*
	 * @brief: Construct that receive an ECC public key generate previously
	 * @param: ECC public key. It can be content stored in a string or file path.
	 * @param: ECC private key. It can be content stored in a string or file path.
	 * @return: bool - true if param is file
	 */
	PKIECC(std::string file_pub_path, std::string file_prv_path,bool arefile);

	/*
	 * @brief: It make digital signature from a message receive as param.
	 * However, it can be throw std::runtime_error if RSA private key is nullptr,
	 * message has length equal to 0 or signature failed
	 * @param: Message to be signed
	 * @return: Signature's string
	 */
	std::string SignMessage(std::string ) override final;
	/*
	 * @brief: Check the signature and a text plan
	 * @param: text to be verified
	 * @param: text's signature
	 * @return: True if signature is ok, false, otherwise.
	 */
	bool VerifySignatureMessage(std::string text, std::string signature) override final;

	/*
	 * @brief: established ECDH using ECC pair key and use a shared secret to encrypt a text using AES ECB mode
	 * @param: message to be encrypted. Throw exception if text is empty or private key is nullptr
	 * @return: return a text encrypted
	 */
	std::string EncryptMessage(const std::string& ) override final;
	/*
	 * @brief: established ECDH using ECC pair key and use a shared secret to decrypt a text using AES ECB mode
	 * @param: message to be decrypted. Throw exception if text is empty or private key is nullptr
	 * @return: return a plain text
	 */
	std::string DecryptMessage(const std::string&) override final;

	/*
	 * @brief: Store ECC Public Key in a file
	 * @param: File path to store ECC Public Key
	 * @return:
	 */
	void SavePubKey(std::string ) override final;
	/*
	 * @brief: Store ECC Private Key in a file
	 * @param: File path to store ECC Private Key
	 * @return:
	 */
	void SavePrvKey(std::string ) override final;
	/*
	 * @brief: Store ECC Public Key in a string
	 * @param:
	 * @return: Return a ECC Public Key in a string with PEM format
	 */
	std::string SavePubKey() override final;
	/*
	 * @brief: Store ECC Private Key in a string
	 * @param:
	 * @return: Return a ECC Private Key in a string with PEM format
	 */
	std::string SavePrvKey() override final;
	/*
	 * @brief: Method to generate a certificate requisition in a PEM format
	 * @param: request_data is a data structure that stores a client information
	 * @return: Certificate's requisition in a string with PEM format
	 */
	std::string GenerateRequest(const request_data&);
	/*
	 * @brief: Method to generate a certificate self signed and return it in a string
	 * @param: Certificate requistion's string in PEM format
	 * @return: Certificate's string in PEM format
	 */
	std::string SelfSign(std::string);


	void SetOtherPubKeyECDH(std::string);


	std::string CalculateECDH();


	PKIECC(const PKIECC&)=delete;


	PKIECC&operator=(const PKIECC&)=delete;

	~PKIECC();
private :
	std::string GenerateSecret();
	EVP_PKEY *PubKey=nullptr,*PrvKey=nullptr,*OtherPub=nullptr;
	X509 * Cert=nullptr;
};

class PKICertificate : public  InterfacePKI::SignatureDigital, public InterfacePKI::Confidentiality, public InterfacePKI::StreamStore
{
public :
	PKICertificate() =delete;
	bool isExpired();
	PKICertificate(std::string file_cert_path ,std::string crlpath, bool isfile);
	PKICertificate(std::string file_cert_path , std::string file_prv_path, std::string crlpath, bool arefiles);
	std::string SignMessage(std::string in);
	bool VerifySignatureMessage(std::string text, std::string signature);
	std::string EncryptMessage(const std::string&plain) override final;
	std::string DecryptMessage(const std::string& encrypted) override final;
	std::string SignCert(const struct Requisition&, int  serial, std::vector<std::string>);
	bool VerifySignatureCert(const std::string,bool);
	bool VerifySubjectName(std::string );
	bool VerifyOwnCRL( );
	void UpdateCrl(std::string , bool);
	std::string GetSerial();
	PKICertificate&CreateCRL(std::string);
	PKICertificate&RevokeCert(std::string,bool);
	void SaveCRL(std::string );
	/*
	 * @brief: Store  Public Key in a file
	 * @param: File path to store  Public Key
	 * @return:
	 */
	void SavePubKey(std::string ) override final;
	/*
	 * @brief: Store  Private Key in a file
	 * @param: File path to store  Private Key
	 * @return:
	 */
	void SavePrvKey(std::string ) override final;
	/*
	 * @brief: Store Public Key in a string
	 * @param:
	 * @return: Return a Public Key in a string with PEM format
	 */
	std::string SavePubKey() override final;
	/*
	 * @brief: Store Private Key in a string
	 * @param:
	 * @return: Return a Private Key in a string with PEM format
	 */
	std::string SavePrvKey() override final;
	TypeAlgorithm GetType()
	{
		return Type;
	}
	~PKICertificate();
private :
	std::string PubKeyToStr(EVP_PKEY*);
	std::string CertToStr(X509 * );
	bool VerifyCRLOk(X509 *);
	bool VerifyValidDataOk(X509 *);
	X509_CRL * Crl=nullptr;;
	X509 * Cert=nullptr;
	TypeAlgorithm Type=TypeAlgorithm::not_found;
	union
	{
		PKIECC * Ecc;
		PKIRSA * Rsa;
	};
};

}


#endif /* PKI___HPP_ */
