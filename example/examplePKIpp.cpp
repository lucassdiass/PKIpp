/*
 * examplePKIpp.cpp
 *
 *  Created on: 23 de jan de 2022
 *      Author: Lucas Vargas Dias
 */
#include <PKISymmetric.hpp>
#include <PKI++.hpp>

#include <assert.h>

using namespace PKI::Symmetric;
int main()
{
	std::string plain{"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"}, output{},encrypted{}, mac{}, passwrod{"examplepassword"};
/*	for(int i =0;i<1400;i++)
	{
		plain.push_back((i%9)+48);
	}*/
	::AesCBCMode cbc;
	::AesECBMode ecb;
	::AesCFBMode cfb;
	::AesOFBMode ofb;
	::AesCTRMode ctr;
	::CMACMode cmac;
	::HMACMode hmac;
	::AesGCMMode gcm;
	::AesCCMMode ccm;
	std::cout << "ECB\n\n";
	ecb.ConfigureKey(passwrod);
	encrypted=ecb.EncryptMessage(plain);
	output=ecb.DecryptMessage(encrypted);
	assert(output==plain);
	std::cout << "OK\n";

	std::cout << "CBC\n\n";
	cbc.ConfigureKey(passwrod);
	cbc.ConfigureIV("");
	encrypted=cbc.EncryptMessage(plain);
	output=cbc.DecryptMessage(encrypted);
	assert(output==plain);
	std::cout << "OK\n";

	std::cout << "CFB\n\n";
	cfb.ConfigureKey(passwrod);
	cfb.ConfigureIV("");
	encrypted=cfb.EncryptMessage(plain);
	output=cfb.DecryptMessage(encrypted);
	assert(output==plain);
	std::cout << "OK\n";

	std::cout << "OFB\n\n";
	ofb.ConfigureKey(passwrod);
	ofb.ConfigureIV("");
	encrypted=ofb.EncryptMessage(plain);
	output=ofb.DecryptMessage(encrypted);
	assert(output==plain);
	std::cout << "OK\n";
	std::cout << "CTR\n\n";
	ctr.ConfigureKey(passwrod);
	ctr.ConfigureIV("");
	encrypted=ctr.EncryptMessage(plain);
	output=ctr.DecryptMessage(encrypted);
	assert(output==plain);
	std::cout << "OK\n";

	std::cout << "CMAC\n\n";
	cmac.ConfigureKey("123456789123456678901234567681938123ewewq");

	output=cmac.GenerateMAC(plain);
	bool ok=cmac.VerifyMAC(plain, output);
	assert(ok==true);
	std::cout << "OK\n";
	std::cout << "GCM\n\n";
	gcm.ConfigureIV("");
	gcm.ConfigureKey("");
	mac=gcm.EncryptAuthMessage(plain, encrypted);
	ok=gcm.DecryptVerifyMessage(encrypted, mac, output);
	assert(output==plain);
	assert(ok==true);
	std::cout << "OK\n";
	std::cout << "CCM\n\n";
	ccm.ConfigureIV("");
	ccm.ConfigureKey("");
	mac=ccm.EncryptAuthMessage(plain, encrypted);


	ok=ccm.DecryptVerifyMessage(encrypted, mac, output);
	assert(output==plain);
	assert(ok==true);

	std::cout << "\nOK\n";

	std::cout << "\nECB+HMAC\n";
	ecb.ConfigureKey(passwrod);
	hmac.ConfigureKey("");

	encrypted=ecb.EncryptMessage(plain);
	mac=hmac.GenerateMAC(encrypted);
	ok=hmac.VerifyMAC(encrypted, mac);
	if(ok)
	{
		plain=ecb.DecryptMessage(encrypted);
	}

	assert(output==plain);
	assert(ok==true);

	std::cout << "OK\n";


}




