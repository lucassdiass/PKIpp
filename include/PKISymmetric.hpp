/*
 * PKISymmetric.hpp
 *
 *  Created on: 4 de jan de 2021
 *      Author: root
 */

#ifndef PKISYMMETRIC_HPP_
#define PKISYMMETRIC_HPP_
#include "Interface.hpp"
#include <openssl/evp.h>

namespace PKI
{
namespace Symmetric
{

class AesECBMode : public InterfacePKI::Confidentiality, public InterfacePKI::SymmetricKey
{
public :
	AesECBMode() =default;
	void ConfigureKey(std::string)  override final;
	void ConfigureIV(std::string)  override final
			{

			}

	std::string EncryptMessage(const std::string& )  override final;
	std::string DecryptMessage(const std::string& ) override final;
	~AesECBMode() =default;
private :
	std::string SecretKey;
};
class AesCBCMode : public InterfacePKI::Confidentiality, public InterfacePKI::SymmetricKey
{
public :
	AesCBCMode() =default;
	void ConfigureKey(std::string)  override final;
	void ConfigureIV(std::string)  override final;
	std::string EncryptMessage(const std::string& )  override final;
	std::string DecryptMessage(const std::string& ) override final;
	~AesCBCMode() =default;
private :
	std::string SecretKey, IV;
};
class AesOFBMode : public InterfacePKI::Confidentiality, public InterfacePKI::SymmetricKey
{
public :
	AesOFBMode() =default;
	void ConfigureKey(std::string)  override final;
	void ConfigureIV(std::string)  override final;
	std::string EncryptMessage(const std::string& )  override final;
	std::string DecryptMessage(const std::string& ) override final;
	~AesOFBMode() =default;
private :
	std::string SecretKey, IV;
};
class AesCFBMode : public InterfacePKI::Confidentiality, public InterfacePKI::SymmetricKey
{
public :
	AesCFBMode() =default;
	void ConfigureKey(std::string)  override final;
	void ConfigureIV(std::string) ;

	std::string EncryptMessage(const std::string&)  override final;
	std::string DecryptMessage(const std::string&) override final;
	~AesCFBMode() =default;
private :
	std::string SecretKey, IV;
};
class AesCTRMode : public InterfacePKI::Confidentiality, public InterfacePKI::SymmetricKey
{
public :
	AesCTRMode() =default;
	void ConfigureKey(std::string)  override final;
	void ConfigureIV(std::string)   override final;
	std::string EncryptMessage(const std::string& )  override final;
	std::string DecryptMessage(const std::string& ) override final;
	~AesCTRMode() =default;
private :
	std::string SecretKey, CTR;
};

//////////////////AUTHENTICATION/////////////////////

class CMACMode : public InterfacePKI::AuthenticationMode, public InterfacePKI::SymmetricKey
{
public :
	CMACMode() =default;
	void ConfigureKey(std::string)  override final;
	void ConfigureIV(std::string)   override final
			{

			}
	bool VerifyMAC(std::string text, std::string mac)  override final;
	std::string GenerateMAC(std::string text) override final;
	~CMACMode() =default;
private :
	std::string SecretKey;
};
class HMACMode : public InterfacePKI::AuthenticationMode, public InterfacePKI::SymmetricKey
{
public :
	HMACMode() =default;
	void ConfigureKey(std::string)  override final;
	void ConfigureIV(std::string)   override final
			{

			}
	bool VerifyMAC(std::string text, std::string mac)  override final;
	std::string GenerateMAC(std::string text) override final;
	~HMACMode() =default;
private :
	std::string SecretKey;
};

//////////////////confidentiality and authentication/////////////////////

class AesCCMMode : public InterfacePKI::ConfidentialityAuth, public InterfacePKI::SymmetricKey
{
public :
	AesCCMMode() =default;
	void ConfigureKey(std::string)  override final;
	void ConfigureIV(std::string)   override final;
	std::string EncryptAuthMessage(std::string plain , std::string&encrypted)  override final;
	bool  DecryptVerifyMessage(std::string encrypted , std::string mac, std::string&plain);

	~AesCCMMode() =default;
private :
	std::string SecretKey, IV;
};

class AesGCMMode : public InterfacePKI::ConfidentialityAuth,  public InterfacePKI::SymmetricKey
{
public :
	AesGCMMode() =default;
	void ConfigureKey(std::string)  override final;
	void ConfigureIV(std::string)   override final;
	std::string EncryptAuthMessage(std::string plain , std::string&encrypted)  override final;
	bool  DecryptVerifyMessage(std::string encrypted , std::string mac, std::string&plain);

	~AesGCMMode() =default;
private :
	std::string SecretKey, IV;
};

}
}



#endif /* PKISYMMETRIC_HPP_ */
