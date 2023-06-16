const API = "https://api.testnet.klever.finance"
const NODE = "https://node.testnet.klever.finance"
function debugWallet(tag, w) {
  let data = JSON.stringify({chain: w.getChain(), baseChain: w.getBaseChain().getName(), address: w.getAddress(), privateKey: w.getPrivateKey(), publicKey: w.getPublicKey(), mnemonic: w.getMnemonic(), path: w.getPath()})
  document.getElementById("demo").innerHTML += "<br><b>"+tag+":</b>"+data+"<br>";
  console.log(tag, data);
}

// import kos to window on load
import("../kos/kos.js").then((kos) => {
  window.kos = kos;
});

// wait for kos to be loaded
function waitForKOS() {
  return new Promise(load)
  function load(resolve, reject) {
    if (typeof window.kos !== "undefined")
      resolve(window.kos);
    else
      setTimeout(load.bind(this, resolve, reject), 250);
  };
}

async function deriveAccounts(){
  console.log("loading kos...");
  const kos = await waitForKOS();
  console.log("loaded kos", kos);

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
      );
      debugWallet("mnemonic", w1);

      // create a random wallet
      let w2 = new kos.Wallet(d.chain);
      debugWallet("random", w2);
    });
  } catch (e) {
    document.body.innerHTML += "<br><br><br><b>error:</b>"+e+"<br>";
  }
}

deriveAccounts();

window.onload = function(){
  var buttonSend = document.getElementById('btnSendKLV');
  buttonSend.onclick = function() {
    sendKLV("klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy", "klv1x2ejsdqz8uccl7htu4cef63z0cqnydhkd8g36tgk6qdv94hu7syqms3spm", 10)
  };

  var buttonWM = document.getElementById('btnWMFlow');
  buttonWM.onclick = function() {
    wmFlow()
  };
}

async function sendKLV(address, to, amount, token = "KLV") {
    const kos = window.kos;
    let klvWallet = kos.Wallet.fromMnemonic(
      kos.Chain.KLV,
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      kos.KLV.getPath(0),
    );

    klvWallet.setNodeUrl(NODE);

    const tx = await klvWallet.send(to, kos.BigNumber.fromString("10"));

    await signAndBroadcast(tx, klvWallet);
}

async function signAndBroadcast(tx, wallet) {
  try {
    console.log({tx: tx.toString()});
    const toSend = wallet.sign(tx);
    console.log({txSigned: toSend.toString()});
    const result = await wallet.broadcast(toSend);
    console.log("TXHash:", result.hash().toString());
  }catch(e){
    console.log(e)
  }
}

async function wmFlow() {
  const WMPass = "12345678";
  console.log("loading kos...");
  const kos = await waitForKOS();
  console.log("loaded kos", kos);

  // new mnemonic
  const mnemonic = kos.generateMnemonicPhrase(12);
  console.log({mnemonic});
  // init wallet manager
  const wm = new kos.WalletManager();
  console.log("WM Is Locked:", wm.isLocked());
  
  try {
    // should give error as default mnemonic not exists yet
    wm.newWallet(kos.Chain.KLV, WMPass);
  } catch (e) {
    console.log("expected error:", e);
  }

  // set default mnemonic
  wm.setMnemonic(mnemonic, WMPass);

  const w1 = wm.newWallet(kos.Chain.KLV, WMPass);
  let wallets = wm.viewWallets();
  console.log({wallets, w1, "w1Address": w1.getAddress()});

  try {
    // try lock with different password
    wm.lock("1234");
  } catch (e) {
    console.log("expected error:", e);
  }

  console.log("WM Is Locked:", wm.isLocked());
  // lock with correct password
  wm.lock(WMPass);
  console.log("WM Is Locked:", wm.isLocked());
  
  try {
    // save wallet manager wrong password
    wm.toPem("1234");
  } catch (e) {
    console.log("expected error:", e);
  }

  //save wallet manager
  const pem = wm.toPem(WMPass);
  console.log("pem", String.fromCharCode(...pem));
  
  // load wallet manager  
  const wm2 = kos.WalletManager.fromPem(pem, WMPass);
  console.log({wm2});

  let walletsLoaded = wm.viewWallets();
  console.log({"isLocked": wm2.isLocked(), walletsLoaded});

  // unlock wallet manager
  wm2.unlock(WMPass);
  walletsLoaded = wm2.viewWallets();
  console.log({"isLocked": wm2.isLocked(), walletsLoaded});

  // get wallet from loaded wallet manager
  const w2 = wm2.getWallet(w1.getChain(), w1.getAddress());
  console.log({w2, "w2Address": w2.getAddress(), "privateKey": w2.getPrivateKey(), "publicKey": w2.getPublicKey(), "mnemonic": w2.getMnemonic(), "path": w2.getPath()});
  // unlock wallet to access secrets
  w2.unlock(WMPass);
  console.log({w2, "w2Address": w2.getAddress(), "privateKey": w2.getPrivateKey(), "publicKey": w2.getPublicKey(), "mnemonic": w2.getMnemonic(), "path": w2.getPath()});
}

wmFlow();