/*
 * ConfidentialityTest.cc
 *
 *  Created on: 15 de abr de 2022
 *      Author: Lucas Dias
 */
#include <gtest/gtest.h>
#include <memory>
#include <PKIpp/PKISymmetric.hpp>
class ConfidentialityTester : public testing::Test {
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
	std::shared_ptr<InterfacePKI::Confidentiality>  enc;
};

TEST_F(ConfidentialityTester, ECBModeOkSize10)
{
	std::string plain{}, encrypted{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::AesECBMode> ecb  (new PKI::Symmetric::AesECBMode);
	EXPECT_NO_THROW(ecb->ConfigureKey(std::string{}));
	enc = ecb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain, enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, ECBModeErrorSize10)
{
	std::string plain{}, encrypted{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::AesECBMode> ecb  (new PKI::Symmetric::AesECBMode);
	EXPECT_NO_THROW(ecb->ConfigureKey(std::string{}));
	enc = ecb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	EXPECT_THROW(enc->DecryptMessage(encrypted), std::runtime_error);
}
TEST_F(ConfidentialityTester, ECBModeOkSize100)
{
	std::string plain{}, encrypted{};
	plain = generateString(100);
	std::shared_ptr<PKI::Symmetric::AesECBMode> ecb  (new PKI::Symmetric::AesECBMode);
	EXPECT_NO_THROW(ecb->ConfigureKey(std::string{}));
	enc = ecb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain, enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, ECBModeErrorSize100)
{
	std::string plain{}, encrypted{};
	plain = generateString(100);
	std::shared_ptr<PKI::Symmetric::AesECBMode> ecb  (new PKI::Symmetric::AesECBMode);
	EXPECT_NO_THROW(ecb->ConfigureKey(std::string{}));
	enc = ecb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	EXPECT_NE(plain, enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, ECBModeOkSize1000)
{
	std::string plain{}, encrypted{};
	plain = generateString(1000);
	std::shared_ptr<PKI::Symmetric::AesECBMode> ecb  (new PKI::Symmetric::AesECBMode);
	EXPECT_NO_THROW(ecb->ConfigureKey(std::string{}));
	enc = ecb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain, enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, ECBModeErrorSize1000)
{
	std::string plain{}, encrypted{};
	plain = generateString(1000);
	std::shared_ptr<PKI::Symmetric::AesECBMode> ecb  (new PKI::Symmetric::AesECBMode);
	EXPECT_NO_THROW(ecb->ConfigureKey(std::string{}));
	enc = ecb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	EXPECT_NE(plain, enc->DecryptMessage(encrypted));
}
/*
This test does not work correctly.
TEST_F(ConfidentialityTester, ECBModeOkSize10000)
{
	std::string plain{}, encrypted{};
	plain = generateString(10000);
	std::shared_ptr<PKI::Symmetric::AesECBMode> ecb  (new PKI::Symmetric::AesECBMode);
	EXPECT_NO_THROW(ecb->ConfigureKey(std::string{}));
	enc = ecb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	std::string aux = enc->DecryptMessage(encrypted);
	EXPECT_EQ(plain, aux);
}
*/
TEST_F(ConfidentialityTester, CTRModeOkSize10)
{
	std::string plain{}, encrypted{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::AesCTRMode> ctr(new PKI::Symmetric::AesCTRMode);
	EXPECT_NO_THROW(ctr->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ctr->ConfigureIV(std::string{}));

	enc = ctr;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, CTRModeErrorSize10)
{
	std::string plain{}, encrypted{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::AesCTRMode> ctr  (new PKI::Symmetric::AesCTRMode);
	EXPECT_NO_THROW(ctr->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ctr->ConfigureIV(std::string{}));
	enc = ctr;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	EXPECT_NE(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, CTRModeOkSize100)
{
	std::string plain{}, encrypted{};
	plain = generateString(100);
	std::shared_ptr<PKI::Symmetric::AesCTRMode> ctr  (new PKI::Symmetric::AesCTRMode);
	EXPECT_NO_THROW(ctr->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ctr->ConfigureIV(std::string{}));
	enc = ctr;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, CTRModeErrorSize100)
{
	std::string plain{}, encrypted{};
	plain = generateString(100);
	std::shared_ptr<PKI::Symmetric::AesCTRMode> ctr  (new PKI::Symmetric::AesCTRMode);
	EXPECT_NO_THROW(ctr->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ctr->ConfigureIV(std::string{}));
	enc = ctr;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	EXPECT_NE(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, CTRModeOkSize1000)
{
	std::string plain{}, encrypted{};
	plain = generateString(1000);
	std::shared_ptr<PKI::Symmetric::AesCTRMode> ctr  (new PKI::Symmetric::AesCTRMode);
	EXPECT_NO_THROW(ctr->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ctr->ConfigureIV(std::string{}));
	enc = ctr;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, CTRModeErrorSize1000)
{
	std::string plain{}, encrypted{};
	plain = generateString(1000);
	std::shared_ptr<PKI::Symmetric::AesCTRMode> ctr  (new PKI::Symmetric::AesCTRMode);
	EXPECT_NO_THROW(ctr->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ctr->ConfigureIV(std::string{}));
	enc = ctr;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	EXPECT_NE(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, CTRModeOkSize10000)
{
	std::string plain{}, encrypted{};
	plain = generateString(10000);
	std::shared_ptr<PKI::Symmetric::AesCTRMode> ctr  (new PKI::Symmetric::AesCTRMode);
	EXPECT_NO_THROW(ctr->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ctr->ConfigureIV(std::string{}));
	enc = ctr;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, CTRModeErrorSize10000)
{
	std::string plain{}, encrypted{};
	plain = generateString(10000);
	std::shared_ptr<PKI::Symmetric::AesCTRMode> ctr  (new PKI::Symmetric::AesCTRMode);
	EXPECT_NO_THROW(ctr->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ctr->ConfigureIV(std::string{}));
	enc = ctr;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	EXPECT_NE(plain,  enc->DecryptMessage(encrypted));
}
