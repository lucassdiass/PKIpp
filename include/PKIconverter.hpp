/*
 * PKIconverter.hpp
 *
 *  Created on: 9 de ago de 2020
 *      Author: Lucas Dias
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

//!< Class to encoder/decoder base64
class Base64
{
public :
	/*
	 * @brief Convert a string to base64.
	 * @param decoded text to be encoded.
	 * @return text encoded
	 */
	std::string Encoder(std::string decoded);

	/*
	 * @brief Convert a string from base64 to original way.
	 * @param encoded text to be decoded.
	 * @return text decoded
	 */
	std::string Decoder(std::string encoded);
};

//!< Class to encoder/decoder hexadecimal
class Hexadecimal
{
public :

	/*
	 * @brief Convert a string to hexadecimal way.
	 * @param decoded text to be encoded.
	 * @return text encoded
	 */
	std::string Encoder(std::string decoded);

	/*
	 * @brief Convert a string from hexadecimal way to original way.
	 * @param encoded text to be decoded.
	 * @return text decoded
	 */
	std::string Decoder(std::string encoded);
};
}
}
#endif /* PKICONVERTER_HPP_ */
