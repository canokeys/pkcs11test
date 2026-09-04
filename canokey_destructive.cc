// Copyright 2026 CanoKey contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#include "pkcs11test.h"

#include <cstring>
#include <string>

namespace pkcs11 {
namespace test {

// ID 06 is the dedicated destructive-test slot (PIV 83). This test never
// accepts an arbitrary ID so a caller cannot accidentally overwrite a normal
// signing or authentication slot.
TEST_F(ReadWriteSessionTest, CanokeyDestructiveGenerateEcP256Id06) {
  if (!g_destructive_piv) {
    TEST_SKIPPED("CanoKey destructive test not enabled (-D)");
    return;
  }
  ASSERT_TRUE(g_expected_serial_set);

  CK_TOKEN_INFO tokenInfo;
  ASSERT_CKR_OK(g_fns->C_GetTokenInfo(g_slot_id, &tokenInfo));
  int serial = 0;
  for (size_t i = 0; i < sizeof(tokenInfo.serialNumber); ++i) {
    if (tokenInfo.serialNumber[i] == ' ')
      break;
    if (tokenInfo.serialNumber[i] < '0' || tokenInfo.serialNumber[i] > '9') {
      serial = -1;
      break;
    }
    serial = serial * 10 + (tokenInfo.serialNumber[i] - '0');
  }
  ASSERT_EQ(static_cast<int>(g_expected_serial), serial)
      << "refusing to overwrite ID 06 on an unexpected token";

  ASSERT_CKR_OK(g_fns->C_Login(session_, CKU_SO, (CK_UTF8CHAR_PTR)g_so_pin,
                               g_so_pin_len));

  CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
  CK_BBOOL publicToken = CK_TRUE;
  CK_BBOOL privateToken = CK_TRUE;
  CK_BBOOL publicPrivate = CK_FALSE;
  CK_BBOOL privatePrivate = CK_TRUE;
  CK_BBOOL verify = CK_TRUE;
  CK_BBOOL sign = CK_TRUE;
  CK_BYTE objectId = 6;
  // DER OID 1.2.840.10045.3.1.7 (NIST P-256).
  CK_BYTE ecParams[] = {0x06, 0x08, 0x2A, 0x86, 0x48,
                        0xCE, 0x3D, 0x03, 0x01, 0x07};
  CK_ATTRIBUTE publicTemplate[] = {
      {CKA_CLASS, &publicClass, sizeof(publicClass)},
      {CKA_ID, &objectId, sizeof(objectId)},
      {CKA_TOKEN, &publicToken, sizeof(publicToken)},
      {CKA_PRIVATE, &publicPrivate, sizeof(publicPrivate)},
      {CKA_VERIFY, &verify, sizeof(verify)},
      {CKA_EC_PARAMS, ecParams, sizeof(ecParams)},
  };
  CK_ATTRIBUTE privateTemplate[] = {
      {CKA_CLASS, &privateClass, sizeof(privateClass)},
      {CKA_ID, &objectId, sizeof(objectId)},
      {CKA_TOKEN, &privateToken, sizeof(privateToken)},
      {CKA_PRIVATE, &privatePrivate, sizeof(privatePrivate)},
      {CKA_SIGN, &sign, sizeof(sign)},
  };
  CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};
  CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
  CK_OBJECT_HANDLE privateKey = CK_INVALID_HANDLE;
  CK_RV rv = g_fns->C_GenerateKeyPair(
      session_, &mechanism, publicTemplate,
      sizeof(publicTemplate) / sizeof(publicTemplate[0]), privateTemplate,
      sizeof(privateTemplate) / sizeof(privateTemplate[0]), &publicKey,
      &privateKey);
  ASSERT_CKR_OK(rv);

  CK_ATTRIBUTE point = {CKA_EC_POINT, NULL_PTR, 0};
  ASSERT_CKR_OK(g_fns->C_GetAttributeValue(session_, publicKey, &point, 1));
  EXPECT_GT(point.ulValueLen, 0U);

  ASSERT_CKR_OK(g_fns->C_Logout(session_));

  CK_ATTRIBUTE findTemplate[] = {
      {CKA_CLASS, &privateClass, sizeof(privateClass)},
      {CKA_ID, &objectId, sizeof(objectId)},
  };
  ASSERT_CKR_OK(g_fns->C_FindObjectsInit(
      session_, findTemplate, sizeof(findTemplate) / sizeof(findTemplate[0])));
  CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
  CK_ULONG foundCount = 0;
  ASSERT_CKR_OK(g_fns->C_FindObjects(session_, &found, 1, &foundCount));
  EXPECT_EQ(0U, foundCount);
  ASSERT_CKR_OK(g_fns->C_FindObjectsFinal(session_));
}

class CanokeyDestructiveRsaTest
    : public ReadWriteSessionTest,
      public ::testing::WithParamInterface<CK_ULONG> {};

TEST_P(CanokeyDestructiveRsaTest, GenerateUseRsaId06) {
  if (!g_destructive_piv) {
    TEST_SKIPPED("CanoKey destructive test not enabled (-D)");
    return;
  }
  ASSERT_TRUE(g_expected_serial_set);

  CK_TOKEN_INFO tokenInfo;
  ASSERT_CKR_OK(g_fns->C_GetTokenInfo(g_slot_id, &tokenInfo));
  int serial = 0;
  for (size_t i = 0; i < sizeof(tokenInfo.serialNumber); ++i) {
    if (tokenInfo.serialNumber[i] == ' ')
      break;
    if (tokenInfo.serialNumber[i] < '0' || tokenInfo.serialNumber[i] > '9') {
      serial = -1;
      break;
    }
    serial = serial * 10 + (tokenInfo.serialNumber[i] - '0');
  }
  ASSERT_EQ(static_cast<int>(g_expected_serial), serial)
      << "refusing to overwrite ID 06 on an unexpected token";

  ASSERT_CKR_OK(g_fns->C_Login(session_, CKU_SO, (CK_UTF8CHAR_PTR)g_so_pin,
                               g_so_pin_len));

  CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_BBOOL token = CK_TRUE;
  CK_BBOOL publicPrivate = CK_FALSE;
  CK_BBOOL privatePrivate = CK_TRUE;
  CK_BBOOL verify = CK_TRUE;
  CK_BBOOL sign = CK_TRUE;
  CK_BBOOL decrypt = CK_TRUE;
  CK_BYTE objectId = 6;
  CK_ULONG modulusBits = GetParam();
  CK_ATTRIBUTE publicTemplate[] = {
      {CKA_CLASS, &publicClass, sizeof(publicClass)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_ID, &objectId, sizeof(objectId)},
      {CKA_TOKEN, &token, sizeof(token)},
      {CKA_PRIVATE, &publicPrivate, sizeof(publicPrivate)},
      {CKA_VERIFY, &verify, sizeof(verify)},
      {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
  };
  CK_ATTRIBUTE privateTemplate[] = {
      {CKA_CLASS, &privateClass, sizeof(privateClass)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_ID, &objectId, sizeof(objectId)},
      {CKA_TOKEN, &token, sizeof(token)},
      {CKA_PRIVATE, &privatePrivate, sizeof(privatePrivate)},
      {CKA_SIGN, &sign, sizeof(sign)},
      {CKA_DECRYPT, &decrypt, sizeof(decrypt)},
  };
  CK_MECHANISM generation = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
  CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
  CK_OBJECT_HANDLE privateKey = CK_INVALID_HANDLE;
  CK_RV rv = g_fns->C_GenerateKeyPair(
      session_, &generation, publicTemplate,
      sizeof(publicTemplate) / sizeof(publicTemplate[0]), privateTemplate,
      sizeof(privateTemplate) / sizeof(privateTemplate[0]), &publicKey,
      &privateKey);
  if (rv == CKR_MECHANISM_INVALID || rv == CKR_KEY_SIZE_RANGE ||
      rv == CKR_FUNCTION_NOT_SUPPORTED) {
    TEST_SKIPPED("RSA size is not configured on this CanoKey");
    g_fns->C_Logout(session_);
    return;
  }
  ASSERT_CKR_OK(rv);

  CK_ULONG actualBits = 0;
  CK_ATTRIBUTE bits = {CKA_MODULUS_BITS, &actualBits, sizeof(actualBits)};
  ASSERT_CKR_OK(g_fns->C_GetAttributeValue(session_, publicKey, &bits, 1));
  EXPECT_EQ(modulusBits, actualBits);
  ASSERT_CKR_OK(g_fns->C_Logout(session_));

  // Exercise public encryption and USER-authenticated private decryption.
  CK_MECHANISM rsaPkcs = {CKM_RSA_PKCS, NULL_PTR, 0};
  CK_BYTE plaintext[] = "canokey rsa write test";
  CK_BYTE ciphertext[512];
  CK_ULONG ciphertextLen = sizeof(ciphertext);
  ASSERT_CKR_OK(g_fns->C_EncryptInit(session_, &rsaPkcs, publicKey));
  ASSERT_CKR_OK(g_fns->C_Encrypt(session_, plaintext, sizeof(plaintext),
                                 ciphertext, &ciphertextLen));

  ASSERT_CKR_OK(g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin,
                               static_cast<CK_ULONG>(strlen(g_user_pin))));
  CK_BYTE recovered[512];
  CK_ULONG recoveredLen = sizeof(recovered);
  ASSERT_CKR_OK(g_fns->C_DecryptInit(session_, &rsaPkcs, privateKey));
  ASSERT_CKR_OK(g_fns->C_Decrypt(session_, ciphertext, ciphertextLen, recovered,
                                 &recoveredLen));
  EXPECT_EQ(sizeof(plaintext), recoveredLen);
  EXPECT_EQ(0, memcmp(plaintext, recovered, sizeof(plaintext)));

  // Use a raw DigestInfo with CKM_RSA_PKCS to verify the signing path.
  CK_BYTE digestInfo[51] = {
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
      0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
  };
  CK_BYTE signature[512];
  CK_ULONG signatureLen = sizeof(signature);
  memset(digestInfo + 19, 0x42, 32);
  ASSERT_CKR_OK(g_fns->C_SignInit(session_, &rsaPkcs, privateKey));
  ASSERT_CKR_OK(g_fns->C_Sign(session_, digestInfo, sizeof(digestInfo),
                              signature, &signatureLen));
  EXPECT_EQ(modulusBits / 8, signatureLen);
  ASSERT_CKR_OK(g_fns->C_Logout(session_));
}

INSTANTIATE_TEST_SUITE_P(RsaSizes, CanokeyDestructiveRsaTest,
                         ::testing::Values(2048U, 3072U, 4096U));

} // namespace test
} // namespace pkcs11
