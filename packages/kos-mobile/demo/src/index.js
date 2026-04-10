import {
    Wallet,
    PathOptions,
    TransactionChainOptions
} from '@klever/kos-web';

function main() {
    try {
        const chainID = 18; // BCH
        
        const pathOptions = PathOptions.new(0);
        pathOptions.setLegacy(false);
        
        const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        const account = Wallet.fromMnemonicIndex(
            chainID,
            mnemonic,
            pathOptions,
            null,
            null
        );
        
        console.log("Address:", account.getAddress());
        console.log("Public Key:", account.getPublicKey());
        
        const rawTx = "0100000002afa8838dbaa03cd3e4fee38bdcb6a428965559ae941dca5a8f91999cfd6d8b0d0100000000ffffffffdb6d60d4a93a95738e72f641bcdd166c94f6e1f439dfe695e40583997284463c0100000000ffffffff0240420f00000000001976a91434bf902df5d66f0e9b89d0f83fbcad638ad19ae988acea970700000000001976a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac00000000";
        
        // Convert hex to base64 for JavaScript binding
        const hexToBase64 = (hex) => {
            const bytes = new Uint8Array(hex.length / 2);
            for (let i = 0; i < hex.length; i += 2) {
                bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
            }
            return btoa(String.fromCharCode(...bytes));
        };
        
        const prevScript1 = hexToBase64("76a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac");
        const prevScript2 = hexToBase64("76a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac");
        
        const inputAmounts = new BigUint64Array([498870n, 1001016n]);
        const prevScripts = [prevScript1, prevScript2];
        
        const options = TransactionChainOptions.newBitcoinSignOptions(
            inputAmounts,
            prevScripts
        );
        

        // Convert raw transaction hex string to bytes using custom hex decoder
        const hexToUint8Array = (hex) => {
            const bytes = new Uint8Array(hex.length / 2);
            for (let i = 0; i < hex.length; i += 2) {
                bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
            }
            return bytes;
        };
        
        const uint8ArrayToHex = (bytes) => {
            return Array.from(bytes)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        };
        
        const rawTxBytes = hexToUint8Array(rawTx);
        
        const transaction = account.sign(rawTxBytes, options);
        
        const signedRawBytes = transaction.getRawData();
        const signedRaw = uint8ArrayToHex(signedRawBytes);
        
        const expectedRaw = "0100000002afa8838dbaa03cd3e4fee38bdcb6a428965559ae941dca5a8f91999cfd6d8b0d010000006b48304502210099626d28374fa3d1a0034330fee7745ab02db07cd37649e6d3ffbe046ff92e9402203793bee2372ab59a05b45188c2bace3b48e73209a01e4d5d862925971632c80a412102bbe7dbcdf8b2261530a867df7180b17a90b482f74f2736b8a30d3f756e42e217ffffffffdb6d60d4a93a95738e72f641bcdd166c94f6e1f439dfe695e40583997284463c010000006a4730440220447084aae4c6800db7c86b8bc8da675e464991a035b2b4010cde48b64a1013a10220582acfb5265c22eae9c2880e07ae66fc86cbef2e97a2ca1bc513535ba322360d412102bbe7dbcdf8b2261530a867df7180b17a90b482f74f2736b8a30d3f756e42e217ffffffff0240420f00000000001976a91434bf902df5d66f0e9b89d0f83fbcad638ad19ae988acea970700000000001976a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac00000000";
        
        if (signedRaw !== expectedRaw) {
           throw new Error(
                `Signed transaction mismatch.\nExpected: ${expectedRaw}\nGot: ${signedRaw}`
            );
        }

        console.log("\nTransaction signed correctly!");

        console.log("\nSigned raw transaction:");
        console.log(signedRaw + "\n");
    } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));  
        console.error("Error:", err.message);  
        console.error("Stack:", err.stack);  
        process.exitCode = 1; 
    }
}

main();