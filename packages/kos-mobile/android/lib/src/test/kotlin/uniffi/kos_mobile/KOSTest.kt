package uniffi.kos_mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KOSTest {
    @Test
    fun testKOS() {
        val dataToEncrypt = "Hello"
        val password = "password"
        val klvChainId: UInt = 38u
        val mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        val klvPk0 = "8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d"
        val klvAddr0 = "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy"
        val klvPath0 = "m/44'/690'/0'/0'/0'"
        val klvKey0 = "e41b323a571fd955e09cd41660ff4465c3f44693c87f2faea4a0fc408727c8ea"

        val isValidMnemonicValid = validateMnemonic(mnemonic)
        assertTrue(isValidMnemonicValid)

        val isInvalidMnemonicValid =
            validateMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon klv")
        assertFalse(isInvalidMnemonicValid)

        val mnemonic12 = generateMnemonic(12)
        assertTrue(mnemonic12.split(" ").size == 12)

        val mnemonic24 = generateMnemonic(24)
        assertTrue(mnemonic24.split(" ").size == 24)

        val gcmEncryptedData = encryptWithGcm(dataToEncrypt, password)
        assertTrue(gcmEncryptedData.isNotEmpty())

        val cbcEncryptedData = encryptWithCbc(dataToEncrypt, password)
        assertTrue(cbcEncryptedData.isNotEmpty())

        val cfbEncryptedData = encryptWithCfb(dataToEncrypt, password)
        assertTrue(cfbEncryptedData.isNotEmpty())

        val gcmDecryptedData = decrypt(gcmEncryptedData, password)
        assertEquals(dataToEncrypt, gcmDecryptedData)

        val cbcDecryptedData = decrypt(cbcEncryptedData, password)
        assertEquals(dataToEncrypt, cbcDecryptedData)

        val cfbDecryptedData = decrypt(cfbEncryptedData, password)
        assertEquals(dataToEncrypt, cfbDecryptedData)

        val walletFromMnemonic = generateWalletFromMnemonic(mnemonic, klvChainId, 0u, false)
        assertEquals(klvChainId, walletFromMnemonic.chainId)
        assertEquals(klvPk0, walletFromMnemonic.privateKey)
        assertEquals(klvAddr0, walletFromMnemonic.address)
        assertEquals(klvPath0, walletFromMnemonic.path)
        assertEquals(klvKey0, walletFromMnemonic.publicKey)

        val walletFromPk = generateWalletFromPrivateKey(klvChainId, klvPk0)
        assertEquals(klvChainId, walletFromPk.chainId)
        assertEquals(klvPk0, walletFromPk.privateKey)
        assertEquals(klvAddr0, walletFromPk.address)
        assertEquals("", walletFromPk.path)
        assertEquals(klvKey0, walletFromPk.publicKey)
    }
}