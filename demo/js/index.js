console.log("AA")


function debug(tag, w) {
  let data = JSON.stringify({chain: w.getChain(), baseChain: w.getBaseChain().getName(), address: w.getAddress(), privateKey: w.getPrivateKey(), publicKey: w.getPublicKey(), mnemonic: w.getMnemonic(), path: w.getPath()})
  document.body.innerHTML += "<br><b>"+tag+":</b>"+data+"<br>";
  console.log(tag, data);
}

import("../kos/kos.js").then((kos) => {
  try {
    [
      {chain: kos.Chain.TRX, model: kos.TRX},
      {chain: kos.Chain.KLV, model: kos.KLV},
    ].forEach((d) => {
      // create new wallet from mnemonic
      let w1 = kos.Wallet.fromMnemonic(
        d.chain,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        d.model.getPath(0),
      ) ;
      debug("mnemonic", w1);

      // create a random wallet
      let w2 = new kos.Wallet(d.chain);
      debug("random", w2);
    });
  } catch (e) {
    console.log("eeee",e);
    document.body.innerHTML += "<br><br><br><b>error:</b>"+e+"<br>";
  }
});
