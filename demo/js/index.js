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

  var btnCreateMnemonic = document.getElementById('btnCreateMnemonic');
  btnCreateMnemonic.onclick = function() {
    createMnemonicAndExport()
  };

  var btnLoadMnemonic = document.getElementById('btnLoadMnemonic');
  btnLoadMnemonic.onclick = function() {
    document.getElementById('fileInput').click();
  };

  document.getElementById('fileInput').addEventListener('change', loadMnemonicFromFile, false);


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
  const wm2 = kos.WalletManager.fromPem(pem);
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

async function cipherFlow() {
  const kos = await waitForKOS();
  const algo = kos.CipherAlgo.GMC;

  const plainText = "Hello World!";
  // can use either of these
  const utf8Encode = new TextEncoder();
  const encoded = utf8Encode.encode(plainText);
  const plainTextBytes = kos.toBytes(plainText);
  console.log({plainTextBytes, encoded});

  
  const encrypted = kos.encrypt(algo, plainTextBytes, "12345678");
  console.log({encrypted});

   // create pem file with encrypted data
   const pem = kos.toPem("MY WALLET", encrypted);
   console.log({pem});

  try {
    // decrypt with wrong password
    kos.decrypt(encrypted, "1234");
  } catch (e) {
    console.log("expected error:", e);
  }
  
  const decrypted = kos.decrypt(encrypted, "12345678");
  console.log({decrypted});

  // compare decrypted data with original data
  const decryptedText = kos.toString(decrypted);
  console.log({decryptedText, plainText});
}
cipherFlow();

async function createMnemonicAndExport() {
  const kos = await waitForKOS();
  const mnemonic = kos.generateMnemonicPhrase(12);

  await exportMnemonic("my wallet", mnemonic);
}

async function exportMnemonic(name, mnemonic) {
  const kos = await waitForKOS();

  try {
    const encrypted = kos.encrypt(kos.CipherAlgo.GMC, kos.toBytes(mnemonic), "12345678");
    const pem = kos.toPem(name, encrypted);

    const qrCode = kos.generateQR(pem);
    const url = URL.createObjectURL(new Blob([qrCode], { type: 'image/png' }));
    document.getElementById('qrCode').src = url;
    console.log({pem, url});
  }catch(e){
    console.log(e)
  }
}


async function loadMnemonicFromFile(e) {
  const file = e.target.files[0];
  const reader = new FileReader();

  reader.onloadend = function() {
      const img = new Image();
      img.onload = function(){
          const canvas = document.createElement('canvas');
          const context = canvas.getContext('2d');

          canvas.width = img.width;
          canvas.height = img.height;
          context.drawImage(img, 0, 0, img.width, img.height);

          const imageData = context.getImageData(0, 0, img.width, img.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height);
          console.log({code});

          // decrypt data
          if (code) {
            // get password from user
            const password = prompt("Please enter password", "");
            // convert code to pem and decrypt
            const mnemonic = kos.fromPem(code.data, password);
            alert("recovered mnemonic: " + kos.toString(mnemonic));
              
          } else {
              alert("QR Code not detected");
          }
      }

      img.src = reader.result;
  }

  if (file) {
      reader.readAsDataURL(file);
  } else {
      alert("No file selected.");
  }

}
