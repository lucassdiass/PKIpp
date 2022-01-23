/*
 * Interface.hpp
 *
 *  Created on: 14 de ago de 2020
 *      Author: root
 */

#ifndef INTERFACE_HPP_
#define INTERFACE_HPP_
#include <bits/stdc++.h>

namespace InterfacePKI
{
class Confidentiality
{
public :
	Confidentiality()=default;
	std::string virtual EncryptMessage(const std::string& ) =0;
	std::string virtual DecryptMessage(const std::string& ) =0;
	virtual ~Confidentiality()=default;
};
class SymmetricKey
{
public:
	void virtual ConfigureKey(std::string) =0;
	void virtual ConfigureIV(std::string) =0;

	virtual ~SymmetricKey()=default;
};

class AuthenticationMode
{
public:
	bool virtual VerifyMAC(std::string text, std::string mac)=0;
	std::string virtual  GenerateMAC(std::string text) =0;
	virtual ~AuthenticationMode()=default;
};

class ConfidentialityAuth
{
public :
	std::string virtual EncryptAuthMessage(std::string plain , std::string&encrypted) =0;
	bool virtual DecryptVerifyMessage(std::string encrypted, std::string mac, std::string&plain) =0;
	virtual ~ConfidentialityAuth() =default;
};

class CipherAuthenticationMode
{
public:
	virtual std::string EncryptAuth(std::string plaintext) =0;
	virtual bool DecryptAuth(std::string ciphertext, std::string&plaintext) =0;
	virtual ~CipherAuthenticationMode()=default;
};
class SignatureDigital
{
public :
	SignatureDigital()=default;
	std::string virtual SignMessage(std::string ) =0;
	bool virtual VerifySignatureMessage(std::string text, std::string signature) =0;
	virtual ~SignatureDigital()=default;
};

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

}

#endif /* INTERFACE_HPP_ */
