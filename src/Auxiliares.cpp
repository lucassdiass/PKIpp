/*
 * PKIconverter.cpp
 *
 *  Created on: 10 de ago de 2020
 *      Author: root
 */

#include "PKIconverter.hpp"
#include <iostream>
using namespace PKI::Converter;
using namespace CryptoPP;
using namespace std;
using namespace PKI;
istream & PKI::operator >> (istream &in,  request_data &c)
{
    std::getline(in,c.szCountry);
    in.clear();
    std::getline(in,c.szProvince);
    in.clear();

    std::getline(in, c.szCity);
    in.clear();

    std::getline(in,c.szOrganization);
    in.clear();

    std::getline(in, c.szCommon);
    in.clear();

    return in;
}

std::string Base64::Encoder(std::string decoded)
{
	try
	{
		CryptoPP::Base64Encoder encoder;
		std::string encoded;
		encoder.Attach( new StringSink( encoded ) );
		encoder.Put( (byte*)decoded.data(), decoded.size() );
		encoder.MessageEnd();
		return encoded;
	}
	catch(...)
	{
		throw;
	}
}
std::string Base64::Decoder(std::string encoded)
{
	try
	{
		std::string decoded;
		CryptoPP::Base64Decoder decoder;
		decoder.Attach( new StringSink( decoded ) );
		decoder.Put( (byte*)encoded.data(), encoded.size() );
		decoder.MessageEnd();
		return decoded;
	}
	catch(...)
	{
		throw;
	}
}
std::string Hexadecimal::Decoder(std::string encoded)
{
	try
	{
		std::string decoded;
		CryptoPP::HexDecoder decoder;
		decoder.Attach( new StringSink( decoded ) );
		decoder.Put( (byte*)encoded.data(), encoded.size() );
		decoder.MessageEnd();
		return decoded;
	}
	catch(...)
	{
		throw;
	}
}
std::string Hexadecimal::Encoder(std::string decoded)
{
	try
	{
		CryptoPP::HexEncoder encoder;
		std::string encoded;
		encoder.Attach( new StringSink( encoded ) );
		encoder.Put( (byte*)decoded.data(), decoded.size() );
		encoder.MessageEnd();
		return encoded;
	}
	catch(...)
	{
		throw;
	}
}
