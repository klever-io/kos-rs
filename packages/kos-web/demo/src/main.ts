const API = "https://api.testnet.klever.org";
const NODE = "https://node.testnet.klever.org";
import jsQR from "jsqr";
import * as kos from "kos";

const KLV_ID = 38;

function debugWallet(tag: string, w: kos.Wallet) {
  let data = JSON.stringify({
    chain: w.getChain(),
    address: w.getAddress(),
    privateKey: w.getPrivateKey(),
    publicKey: w.getPublicKey(),
    mnemonic: w.getMnemonic(),
    path: w.getPath(),
  });

  let demo = document.getElementById("demo");

  if (!demo) {
    return;
  }

  demo.innerHTML += "<br><b>" + tag + ":</b>" + data + "<br>";
  console.log(tag, data);
}

async function deriveAccounts() {
  console.log("loading kos...");
  console.log("loaded kos", kos);

  try {
    [{ chain: 1 }, { chain: KLV_ID }].forEach((d) => {
      // get path options
      const pathOptions = kos.PathOptions.new(0);

      // create new wallet from mnemonic
      let w1 = kos.Wallet.fromMnemonicIndex(
        d.chain,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        pathOptions
      );
      debugWallet("mnemonic", w1);
    });
  } catch (e) {
    document.body.innerHTML += "<br><br><br><b>error:</b>" + e + "<br>";
  }
}

deriveAccounts();

window.onload = function () {
  var btnCreateMnemonic = document.getElementById("btnCreateMnemonic");
  var btnLoadMnemonic = document.getElementById("btnLoadMnemonic");
  var fileInput = document.getElementById("fileInput");

  var buttonWM = document.getElementById("btnWMFlow");

  if (!btnCreateMnemonic || !btnLoadMnemonic || !fileInput || !buttonWM) {
    return;
  }

  btnCreateMnemonic.onclick = function () {
    createMnemonicAndExport();
  };

  btnLoadMnemonic.onclick = function () {
    document.getElementById("fileInput")?.click();
  };

  fileInput.addEventListener("change", loadMnemonicFromFile, false);

  buttonWM.onclick = function () {
    // wmFlow();
  };
};

async function signAndBroadcast(tx: Uint8Array, wallet: kos.Wallet) {
  try {
    console.log({ tx: tx.toString() });
    const toSend = wallet.sign(tx);
    console.log({ txSigned: toSend.toString() });
    // const result = await wallet.broadcast(toSend);
    // console.log("TXHash:", result.hash().toString());
  } catch (e) {
    console.log(e);
  }
}

// async function wmFlow() {
//   const WMPass = "12345678";

//   // new mnemonic
//   const mnemonic = kos.generateMnemonicPhrase(12);
//   console.log({ mnemonic });
//   // init wallet manager
//   const wm = new kos.WalletManager();
//   console.log("WM Is Locked:", wm.isLocked());

//   try {
//     // should give error as default mnemonic not exists yet
//     wm.newWallet(kos.Chain.KLV, WMPass);
//   } catch (e) {
//     console.log("expected error:", e);
//   }

//   // set default mnemonic
//   wm.setMnemonic(mnemonic, WMPass);

//   const w1 = wm.newWallet(kos.Chain.KLV, WMPass);
//   let wallets = wm.viewWallets();
//   console.log({ wallets, w1, w1Address: w1.getAddress() });

//   try {
//     // try lock with different password
//     wm.lock("1234");
//   } catch (e) {
//     console.log("expected error:", e);
//   }

//   console.log("WM Is Locked:", wm.isLocked());
//   // lock with correct password
//   wm.lock(WMPass);
//   console.log("WM Is Locked:", wm.isLocked());

//   try {
//     // save wallet manager wrong password
//     wm.toPem("1234");
//   } catch (e) {
//     console.log("expected error:", e);
//   }

//   //save wallet manager
//   const pem = wm.toPem(WMPass);
//   console.log("pem", String.fromCharCode(...pem));

//   // load wallet manager
//   const wm2 = kos.Wallet.fromPem(pem);
//   console.log({ wm2 });

//   let walletsLoaded = wm.viewWallets();
//   console.log({ isLocked: wm2.isLocked(), walletsLoaded });

//   // unlock wallet manager
//   wm2.unlock(WMPass);
//   walletsLoaded = wm2.viewWallets();
//   console.log({ isLocked: wm2.isLocked(), walletsLoaded });

//   // get wallet from loaded wallet manager
//   const w2 = wm2.getWallet(w1.getChain(), w1.getAddress());
//   console.log({
//     w2,
//     w2Address: w2.getAddress(),
//     privateKey: w2.getPrivateKey(),
//     publicKey: w2.getPublicKey(),
//     mnemonic: w2.getMnemonic(),
//     path: w2.getPath(),
//   });
//   // unlock wallet to access secrets
//   w2.unlock(WMPass);
//   console.log({
//     w2,
//     w2Address: w2.getAddress(),
//     privateKey: w2.getPrivateKey(),
//     publicKey: w2.getPublicKey(),
//     mnemonic: w2.getMnemonic(),
//     path: w2.getPath(),
//   });
// }

async function cipherFlow() {
  const plainText = "Hello World!";
  // can use either of these
  const utf8Encode = new TextEncoder();
  const encoded = utf8Encode.encode(plainText);
  const plainTextBytes = kos.toBytes(plainText);
  console.log({ plainTextBytes, encoded });

  const encrypted = kos.encrypt(plainTextBytes, "12345678");
  console.log({ encrypted });

  // create pem file with encrypted data
  const pem = kos.toPem("MY WALLET", encrypted);
  console.log({ pem });

  try {
    // decrypt with wrong password
    kos.decrypt(encrypted, "1234");
  } catch (e) {
    console.log("expected error:", e);
  }

  const decrypted = kos.decrypt(encrypted, "12345678");
  console.log({ decrypted });

  // compare decrypted data with original data
  const decryptedText = kos.toString(decrypted);
  console.log({ decryptedText, plainText });
}

cipherFlow();

async function createMnemonicAndExport() {
  const mnemonic = kos.generateMnemonicPhrase(12);

  await exportMnemonic("my wallet", mnemonic);
}

async function exportMnemonic(name: string, mnemonic: string) {
  try {
    const encrypted = kos.encrypt(kos.toBytes(mnemonic), "12345678");
    const pem = kos.toPem(name, encrypted);

    const qrCode = kos.generateQR(pem);
    const url = URL.createObjectURL(new Blob([qrCode], { type: "image/png" }));
    let element = document.getElementById("qrCode");
    if (!element) return;

    (element as HTMLImageElement).src = url;
    console.log({ pem, url });
  } catch (e) {
    console.log(e);
  }
}

async function loadMnemonicFromFile(e: Event) {
  const file = (e.target as HTMLInputElement)?.files?.[0];
  const reader = new FileReader();

  reader.onloadend = function () {
    const img = new Image();
    img.onload = function () {
      const canvas = document.createElement("canvas");
      const context = canvas.getContext("2d");

      if (!context) {
        alert("Failed to get canvas context");
        return;
      }

      canvas.width = img.width;
      canvas.height = img.height;
      context.drawImage(img, 0, 0, img.width, img.height);

      const imageData = context.getImageData(0, 0, img.width, img.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      console.log({ code });

      // decrypt data
      if (code) {
        // get password from user
        const password = prompt("Please enter password", "");

        if (!password) {
          alert("Password is required");
          return;
        }
        // convert code to pem and decrypt
        const mnemonic = kos.fromPem(code.data, password);
        alert("recovered mnemonic: " + kos.toString(mnemonic));
      } else {
        alert("QR Code not detected");
      }
    };

    img.setAttribute("src", reader.result as string);
  };

  if (file) {
    reader.readAsDataURL(file);
  } else {
    alert("No file selected.");
  }
}
