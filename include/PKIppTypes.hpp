/*
 * PKIppTypes.hpp
 *
 *  Created on: 22 de set de 2022
 *      Author: Lucas Dias
 */

#ifndef PKIPPTYPES_HPP_
#define PKIPPTYPES_HPP_

#include <bits/stdc++.h>
#include <openssl/evp.h>

typedef std::shared_ptr<EVP_PKEY> EVP_PKEY_ptr;
typedef std::shared_ptr<X509> X509_ptr;

#endif /* PKIPPTYPES_HPP_ */
