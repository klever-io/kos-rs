console.log("AA")


function debug(tag, w) {
  let data = JSON.stringify({chain: w.getChain(), address: w.getAddress()})
  document.body.innerHTML += "<br><b>"+tag+":</b>"+data+"<br>";
  console.log(tag, data);
}

import("../kos/kos.js").then((kos) => {
  try {
    // create random mnemonic
    let m = kos.generateMnemonicPhrase(12);
    console.log("mnemonic phrase", m);
    // create new wallet from mnemonic
    let w1 = kos.Wallet.fromMnemonic(
      kos.Chain.TRX,
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      "m/44'/195'/0'/0/0",
    ) ;
    debug("mnemonic", w1);
    // create a random wallet
    let w2 = kos.Wallet.new(kos.Chain.TRX);
    debug("random", w2);
  } catch (e) {
    console.log("eeee",e);
  }
});
