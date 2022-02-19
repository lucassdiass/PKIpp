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
	 * \brief signature of encrypt method.
	 * \param plain String to be encrypted.
	 * \return Message encrypted
	 */
	std::string virtual EncryptMessage(const std::string& plain) =0;

	/*
	 * \brief signature of decrypt method.
	 * \param encrypted String to be decrypted.
	 * \return Text plain
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
	 * \brief Configure the initialization vector to be used.
	 * \param new_key The initialization vector to be used.
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
	 * \brief Verify the MAC from text.
	 * \param Text string to be MAC verified.
	 * \param MAC message authentication code.
	 * \return True, if MAC is correct, false otherwise.
	 */
	bool virtual VerifyMAC(std::string text, std::string mac)=0;

	/*
	 * \brief Compute the MAC from a text.
	 * \param text Input of the MAC generation.
	 * \return The message authentication code.
	 */
	std::string virtual  GenerateMAC(std::string text) =0;

	/*
	 * \brief Destructor
	 */
	virtual ~AuthenticationMode()=default;
};

//<! Interface to the encryption+authentication mode
class ConfidentialityAuth
{
public :

	/*
	 * \brief Encrypt text plain and calculate the authentication code.
	 * \param plain Text to be encrypted and authentication code calculated.
	 * \param encrypted Store the result of the plain text encryption
	 * \return Authentication Code
	 */
	std::string virtual EncryptAuthMessage(std::string plain , std::string&encrypted) =0;

	/*
	 * \brief Encrypt text plain and calculate the authentication code.
	 * \param encrypt Store the result of the plain text encryption
	 * \param mac The authentication code to verification.
	 * \param plain Store the result of the decryption.
	 * \return True, if text is decrypted and mac is ok, false otherwise
	 */
	bool virtual DecryptVerifyMessage(std::string encrypted, std::string mac, std::string&plain) =0;

	/*
	 * \brief Destructor
	 */
	virtual ~ConfidentialityAuth() =default;
};


//<! Interface to the signature digital operations
class SignatureDigital
{
public :

	/*
	 * \brief Compute the digital signature from text.
	 * \param text Message do be signed.
	 * \return The signature digital.
	 */
	std::string virtual SignMessage(std::string text) =0;

	/*
	 * \brief Verify the digital signature from text.
	 * \param text Input text of digital signature.
	 * \param signature Digital signature do be verified.
	 * \return True, if signature is correspondent to text, false otherwise.
	 */
	bool virtual VerifySignatureMessage(std::string text, std::string signature) =0;

	/*
	 * \brief Destructor
	 */
	virtual ~SignatureDigital()=default;
};

//<! Interface to StreamStore. Save public/private keys to files or export them to std::string.
class StreamStore
{
public:

	/*
	 * \brief Save the string of public key in a file.
	 * \param pub_path File path to save the public key.
	 */
	void virtual SavePubKey(std::string pub_path) =0;

	/*
	 * \brief Save the string of private key in a file.
	 * \param prv_path File path to save the private key.
	 */
	void virtual SavePrvKey(std::string prv_path) =0;

	/*
	 * \brief Save the string of public key in string way.
	 * \return String of the public key.
	 */
	std::string virtual SavePubKey() =0;

	/*
	 * \brief Save the string of private key in string way.
	 * \return String of the private key.
	 */
	std::string virtual SavePrvKey() =0;

	/*
	 * \brief Destructor
	 */
	virtual ~StreamStore()=default;
};

} //namespace InterfacePKI

#endif /* INTERFACE_HPP_ */
