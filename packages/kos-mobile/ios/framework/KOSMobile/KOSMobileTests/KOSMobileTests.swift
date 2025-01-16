//
//  KOSMobileTests.swift
//  KOSMobileTests
//
//  Created by Daniel Falcão on 21/08/24.
//

import XCTest
@testable import KOSMobile

final class KOSMobileTests: XCTestCase {

    func testKOS() {
        
        let dataToEncrypt = "Hello"
        let password = "password"
        let klvChainId = Int32(38)
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let klvPk0 = "8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d"
        let klvAddr0 = "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy"
        let klvPath0 = "m/44'/690'/0'/0'/0'"
        let klvKey0 = "e41b323a571fd955e09cd41660ff4465c3f44693c87f2faea4a0fc408727c8ea"
        
        let isValidMnemonicValid = validateMnemonic(mnemonic: mnemonic)
        XCTAssertTrue(isValidMnemonicValid)
        
        let isInvalidMnemonicValid = validateMnemonic(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon klv")
        XCTAssertFalse(isInvalidMnemonicValid)
        
        let mnemonic12 = try! generateMnemonic(size: 12)
        XCTAssertTrue(mnemonic12.split(separator: " ").count == 12)
        
        let mnemonic24 = try! generateMnemonic(size: 24)
        XCTAssertTrue(mnemonic24.split(separator: " ").count == 24)
        
        let gmcEncryptedData = try! encryptWithGmc(data: dataToEncrypt, password: password)
        XCTAssertTrue(!gmcEncryptedData.isEmpty)
        
        let cbcEncryptedData = try! encryptWithCbc(data: dataToEncrypt, password: password)
        XCTAssertTrue(!cbcEncryptedData.isEmpty)
        
        let cfbEncryptedData = try! encryptWithCfb(data: dataToEncrypt, password: password)
        XCTAssertTrue(!cfbEncryptedData.isEmpty)
        
        let gmcDecryptedData = try! decrypt(data: gmcEncryptedData, password: password)
        XCTAssertEqual(dataToEncrypt, gmcDecryptedData)
        
        let cbcDecryptedData = try! decrypt(data: cbcEncryptedData, password: password)
        XCTAssertEqual(dataToEncrypt, cbcDecryptedData)
        
        let cfbDecryptedData = try! decrypt(data: cfbEncryptedData, password: password)
        XCTAssertEqual(dataToEncrypt, cfbDecryptedData)
        
        let walletFromMnemonic = try! generateWalletFromMnemonic(mnemonic: mnemonic, chainId: UInt32(klvChainId), index: 0, useLegacyPath: false)
        XCTAssertEqual(UInt32(klvChainId), walletFromMnemonic.chainId)
        XCTAssertEqual(klvPk0, walletFromMnemonic.privateKey)
        XCTAssertEqual(klvAddr0, walletFromMnemonic.address)
        XCTAssertEqual(klvPath0, walletFromMnemonic.path)
        XCTAssertEqual(klvKey0, walletFromMnemonic.publicKey)
        
        let walletFromPk = try! generateWalletFromPrivateKey(chainId: UInt32(klvChainId), privateKey: klvPk0)
        XCTAssertEqual(UInt32(klvChainId), walletFromPk.chainId)
        XCTAssertEqual(klvPk0, walletFromPk.privateKey)
        XCTAssertEqual(klvAddr0, walletFromPk.address)
        XCTAssertEqual("", walletFromPk.path)
        XCTAssertEqual(klvKey0, walletFromPk.publicKey)
        
    }
}
