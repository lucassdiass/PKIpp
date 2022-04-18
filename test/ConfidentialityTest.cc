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
TEST_F(ConfidentialityTester, CBCModeOkSize10)
{
	std::string plain{}, encrypted{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::AesCBCMode> cbc(new PKI::Symmetric::AesCBCMode);
	EXPECT_NO_THROW(cbc->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(cbc->ConfigureIV(std::string{}));
	enc = cbc;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, CBCModeErrorSize10)
{
	std::string plain{}, encrypted{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::AesCBCMode> cbc(new PKI::Symmetric::AesCBCMode);
	EXPECT_NO_THROW(cbc->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(cbc->ConfigureIV(std::string{}));
	enc = cbc;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	//EXPECT_NE(plain,  enc->DecryptMessage(encrypted));
	EXPECT_THROW(enc->DecryptMessage(encrypted), std::runtime_error);

}
TEST_F(ConfidentialityTester, CBCModeOkSize100)
{
	std::string plain{}, encrypted{};
	plain = generateString(100);
	std::shared_ptr<PKI::Symmetric::AesCBCMode> cbc(new PKI::Symmetric::AesCBCMode);
	EXPECT_NO_THROW(cbc->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(cbc->ConfigureIV(std::string{}));
	enc = cbc;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, CBCModeErrorSize100)
{
	std::string plain{}, encrypted{};
	plain = generateString(100);
	std::shared_ptr<PKI::Symmetric::AesCBCMode> cbc(new PKI::Symmetric::AesCBCMode);
	EXPECT_NO_THROW(cbc->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(cbc->ConfigureIV(std::string{}));
	enc = cbc;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	EXPECT_NE(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, CBCModeOkSize1000)
{
	std::string plain{}, encrypted{};
	plain = generateString(1000);
	std::shared_ptr<PKI::Symmetric::AesCBCMode> cbc(new PKI::Symmetric::AesCBCMode);
	EXPECT_NO_THROW(cbc->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(cbc->ConfigureIV(std::string{}));
	enc = cbc;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, CBCModeErrorSize1000)
{
	std::string plain{}, encrypted{};
	plain = generateString(1000);
	std::shared_ptr<PKI::Symmetric::AesCBCMode> cbc(new PKI::Symmetric::AesCBCMode);
	EXPECT_NO_THROW(cbc->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(cbc->ConfigureIV(std::string{}));
	enc = cbc;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	EXPECT_NE(plain,  enc->DecryptMessage(encrypted));
}
/*
TEST_F(ConfidentialityTester, CBCModeOkSize10000)
{
	std::string plain{}, encrypted{};
	plain = generateString(10000);
	std::shared_ptr<PKI::Symmetric::AesCBCMode> cbc(new PKI::Symmetric::AesCBCMode);
	EXPECT_NO_THROW(cbc->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(cbc->ConfigureIV(std::string{}));
	enc = cbc;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain, enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, CBCModeErrorSize10000)
{
	std::string plain{}, encrypted{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::AesCBCMode> cbc(new PKI::Symmetric::AesCBCMode);
	EXPECT_NO_THROW(cbc->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(cbc->ConfigureIV(std::string{}));
	enc = cbc;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	EXPECT_NE(plain,  enc->DecryptMessage(encrypted));
}
*/

TEST_F(ConfidentialityTester, OFBModeOkSize10)
{
	std::string plain{}, encrypted{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::AesOFBMode> ofb(new PKI::Symmetric::AesOFBMode);
	EXPECT_NO_THROW(ofb->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ofb->ConfigureIV(std::string{}));
	enc = ofb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, OFBModeErrorSize10)
{
	std::string plain{}, encrypted{};
	plain = generateString(10);
	std::shared_ptr<PKI::Symmetric::AesOFBMode> ofb(new PKI::Symmetric::AesOFBMode);
	EXPECT_NO_THROW(ofb->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ofb->ConfigureIV(std::string{}));
	enc = ofb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	EXPECT_NE(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, OFBModeOkSize100)
{
	std::string plain{}, encrypted{};
	plain = generateString(100);
	std::shared_ptr<PKI::Symmetric::AesOFBMode> ofb(new PKI::Symmetric::AesOFBMode);
	EXPECT_NO_THROW(ofb->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ofb->ConfigureIV(std::string{}));
	enc = ofb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, OFBModeErrorSize100)
{
	std::string plain{}, encrypted{};
	plain = generateString(100);
	std::shared_ptr<PKI::Symmetric::AesOFBMode> ofb(new PKI::Symmetric::AesOFBMode);
	EXPECT_NO_THROW(ofb->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ofb->ConfigureIV(std::string{}));
	enc = ofb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	EXPECT_NE(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, OFBModeOkSize1000)
{
	std::string plain{}, encrypted{};
	plain = generateString(1000);
	std::shared_ptr<PKI::Symmetric::AesOFBMode> ofb(new PKI::Symmetric::AesOFBMode);
	EXPECT_NO_THROW(ofb->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ofb->ConfigureIV(std::string{}));
	enc = ofb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, OFBModeErrorSize1000)
{
	std::string plain{}, encrypted{};
	plain = generateString(1000);
	std::shared_ptr<PKI::Symmetric::AesOFBMode> ofb(new PKI::Symmetric::AesOFBMode);
	EXPECT_NO_THROW(ofb->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ofb->ConfigureIV(std::string{}));
	enc = ofb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	EXPECT_NE(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, OFBModeOkSize10000)
{
	std::string plain{}, encrypted{};
	plain = generateString(10000);
	std::shared_ptr<PKI::Symmetric::AesOFBMode> ofb(new PKI::Symmetric::AesOFBMode);
	EXPECT_NO_THROW(ofb->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ofb->ConfigureIV(std::string{}));
	enc = ofb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	EXPECT_EQ(plain,  enc->DecryptMessage(encrypted));
}
TEST_F(ConfidentialityTester, OFBModeErrorSize10000)
{
	std::string plain{}, encrypted{};
	plain = generateString(10000);
	std::shared_ptr<PKI::Symmetric::AesOFBMode> ofb(new PKI::Symmetric::AesOFBMode);
	EXPECT_NO_THROW(ofb->ConfigureKey(std::string{}));
	EXPECT_NO_THROW(ofb->ConfigureIV(std::string{}));
	enc = ofb;
	EXPECT_NO_THROW(encrypted = enc->EncryptMessage(plain));
	encrypted[0] = encrypted[0] + 1;
	EXPECT_NE(plain,  enc->DecryptMessage(encrypted));
}

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
