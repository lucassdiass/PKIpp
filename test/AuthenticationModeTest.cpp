/*
 * AuthenticationModeTest.cpp
 *
 *  Created on: 24 de abr de 2022
 *      Author: root
 */
#include <gtest/gtest.h>
#include <memory>
#include <PKIpp/PKISymmetric.hpp>
class AuthenticationModeTester : public testing::Test {
public:
	std::string generateString(size_t n)
	{
	    std::random_device dev;
	    std::mt19937 rng(dev());
	    std::uniform_int_distribution<std::mt19937::result_type> dist6(32,126);
	    std::string random_string{};
	    for(size_t i = 0; i < n; i++)
	    {
	    	random_string.push_back(dist6(rng));
	    }
	    return random_string;
	}
	std::shared_ptr<InterfacePKI::AuthenticationMode>  auth;
};

TEST_F(AuthenticationModeTester, HMACModeOkSize10)
{
	std::string plain{}, mac{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::HMACMode> hmac(new PKI::Symmetric::HMACMode);
	EXPECT_NO_THROW(hmac->ConfigureKey(std::string{}));
	auth = hmac;
	EXPECT_NO_THROW(mac = auth->GenerateMAC(plain));
	EXPECT_EQ(true, auth->VerifyMAC(plain, mac));
}
TEST_F(AuthenticationModeTester, HMACModeErrorSize10WithDifferentText)
{
	std::string plain{}, mac{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::HMACMode> hmac(new PKI::Symmetric::HMACMode);
	EXPECT_NO_THROW(hmac->ConfigureKey(std::string{}));
	auth = hmac;
	EXPECT_NO_THROW(mac = auth->GenerateMAC(plain));
	plain = generateString(10);
	EXPECT_EQ(false, auth->VerifyMAC(plain, mac));
}
TEST_F(AuthenticationModeTester, HMACModeErrorSize10WithDifferentHMAC)
{
	std::string plain{}, mac{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::HMACMode> hmac(new PKI::Symmetric::HMACMode);
	EXPECT_NO_THROW(hmac->ConfigureKey(std::string{}));
	auth = hmac;
	EXPECT_NO_THROW(mac = auth->GenerateMAC(plain));
    mac = generateString(mac.size());
	EXPECT_EQ(false, auth->VerifyMAC(plain, mac));
}
TEST_F(AuthenticationModeTester, CMACModeOkSize10)
{
	std::string plain{}, mac{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::HMACMode> cmac(new PKI::Symmetric::HMACMode);
	EXPECT_NO_THROW(cmac->ConfigureKey(std::string{}));
	auth = cmac;
	EXPECT_NO_THROW(mac = auth->GenerateMAC(plain));
	EXPECT_EQ(true, auth->VerifyMAC(plain, mac));
}
TEST_F(AuthenticationModeTester, CMACModeErrorSize10WithDifferentText)
{
	std::string plain{}, mac{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::HMACMode> cmac(new PKI::Symmetric::HMACMode);
	EXPECT_NO_THROW(cmac->ConfigureKey(std::string{}));
	auth = cmac;
	EXPECT_NO_THROW(mac = auth->GenerateMAC(plain));
	plain = generateString(10);
	EXPECT_EQ(false, auth->VerifyMAC(plain, mac));
}
TEST_F(AuthenticationModeTester, CMACModeErrorSize10WithDifferentHMAC)
{
	std::string plain{}, mac{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::HMACMode> cmac(new PKI::Symmetric::HMACMode);
	EXPECT_NO_THROW(cmac->ConfigureKey(std::string{}));
	auth = cmac;
	EXPECT_NO_THROW(mac = auth->GenerateMAC(plain));
    mac = generateString(mac.size());
	EXPECT_EQ(false, auth->VerifyMAC(plain, mac));
}
