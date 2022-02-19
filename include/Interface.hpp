/*
 * Interface.hpp
 *
 *  Created on: 14 de ago de 2020
 *      Author: Lucas Dias
 */

#ifndef INTERFACE_HPP_
#define INTERFACE_HPP_
#include <bits/stdc++.h>

namespace InterfacePKI
{

//<! Interface to encrypt/decrypt method
class Confidentiality
{
public :

	/*
	 * \brief Constructor
	 */
	Confidentiality()=default;

	/*
	 *\brief signature of encrypt method.
	 *\param plain String to be encrypted.
	 *\return Message encrypted
	 */
	std::string virtual EncryptMessage(const std::string& plain) =0;

	/*
	 *\brief signature of decrypt method.
	 *\param encrypted String to be decrypted.
	 *\return Text plain
	 */
	std::string virtual DecryptMessage(const std::string& encrypted) =0;

	/*
	 * \brief Destructor
	 */
	virtual ~Confidentiality()=default;
};

//<! Interface to the symmetric key cryptography
class SymmetricKey
{
public:

	/*
	 * \brief Constructor
	 */
	SymmetricKey()=default;

	/*
	 *\brief Recovery the symmetric key to a std::string container.
	 *\return Symmetric key string.
	 */
	std::string virtual RecoveryKey() =0;

	/*
	 *\brief Recovery the initialization vector (IV) to a std::string container.
	 *\return Initialization Vector, or an empty string.
	 */
	std::string virtual RecoveryIV() =0;

	/*
	 *\brief Configure the symmetric key to be used.
	 *\param new_key The new key to be used.
	 */
	void virtual ConfigureKey(std::string new_key) =0;

	/*
	 *\brief Configure the initialization vector to be used.
	 *\param new_key The initialization vector to be used.
	 */
	void virtual ConfigureIV(std::string new_iv) =0;

	/*
	 * \brief Destructor
	 */
	virtual ~SymmetricKey()=default;
};

//<! Interface to the authentication mode.
class AuthenticationMode
{
public:

	/*
	 *\brief Verify the MAC from text.
	 *\param Text string to be MAC verified.
	 *\param MAC message authentication code.
	 *\return True, if MAC is correct, false otherwise.
	 */
	bool virtual VerifyMAC(std::string text, std::string mac)=0;

	/*
	 *\brief Compute the MAC from a text.
	 *\param text Input of the MAC generation.
	 *\return The message authentication code.
	 */
	std::string virtual  GenerateMAC(std::string text) =0;

	/*
	 *\breif Destructor
	 */
	virtual ~AuthenticationMode()=default;
};

//<! Interface to the symmetric key cryptography
class ConfidentialityAuth
{
public :
	std::string virtual EncryptAuthMessage(std::string plain , std::string&encrypted) =0;
	bool virtual DecryptVerifyMessage(std::string encrypted, std::string mac, std::string&plain) =0;
	virtual ~ConfidentialityAuth() =default;
};

//<! Interface to the simmetric key cryptography
class CipherAuthenticationMode
{
public:
	virtual std::string EncryptAuth(std::string plaintext) =0;
	virtual bool DecryptAuth(std::string ciphertext, std::string&plaintext) =0;
	virtual ~CipherAuthenticationMode()=default;
};

//<! Interface to the signature digital operations
class SignatureDigital
{
public :
	SignatureDigital()=default;
	std::string virtual SignMessage(std::string ) =0;
	bool virtual VerifySignatureMessage(std::string text, std::string signature) =0;
	virtual ~SignatureDigital()=default;
};

//<! Interface to StreamStore. Save public/private keys to files or export them to std::string.
class StreamStore
{
public:
	StreamStore()=default;
	void virtual SavePubKey(std::string ) =0;
	void virtual SavePrvKey(std::string ) =0;
	std::string virtual SavePubKey() =0;
	std::string virtual SavePrvKey() =0;
	virtual ~StreamStore()=default;
};

} //namespace InterfacePKI

#endif /* INTERFACE_HPP_ */
