/*
 * PKIconverter.hpp
 *
 *  Created on: 9 de ago de 2020
 *      Author: root
 */

#ifndef PKICONVERTER_HPP_
#define PKICONVERTER_HPP_
#include "PKI++.hpp"
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
namespace PKI
{
namespace Converter
{
class Base64
{
public :
	std::string Encoder(std::string);
	std::string Decoder(std::string);
};

class Hexadecimal
{
public :
	std::string Encoder(std::string);
	std::string Decoder(std::string);
};
}
}
#endif /* PKICONVERTER_HPP_ */
