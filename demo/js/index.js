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
  var button = document.getElementById('btnSendKLV');
  button.onclick = function() {
    sendKLV("klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy", "klv1x2ejsdqz8uccl7htu4cef63z0cqnydhkd8g36tgk6qdv94hu7syqms3spm", 10)
  };
}

// create TX with API (TODO: move to kos)
async function sendKLV(address, to, amount, token = "KLV") {
  const acc = await getAccount(address);
  const tx = await fetch(`${NODE}/transaction/send`, {
    method: 'POST',
    mode: 'cors',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      type: 0,
      sender: address,
      nonce: acc.nonce,
      contracts: [
        {
          kda: token,
          receiver: to,
          amount: amount,
        }
      ]
    }),
  })
    .then(function(response) {
      if (response.ok) {
        return response.json(); // Parse response as JSON
      }
      console.log(response)
      throw new Error('Network response was not ok.');
    })
    .then(function(data) {
      console.log({data});
      return {txHash: data.data.txHash, raw: data.data.result};
    })
    .catch(function(error) {
      console.log('Error:', error.message);
    });

    const kos = window.kos;
    let klvWallet = kos.Wallet.fromMnemonic(
      kos.Chain.KLV,
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      kos.KLV.getPath(0),
    );

    await signAndBroadcast(tx, klvWallet);
}

async function signAndBroadcast(tx, wallet) {
  try {
    console.log({tx});
    const digest = Uint8Array.from(Buffer.from(tx.txHash, 'hex'))
    console.log({digest});
    const signature = wallet.signDigest(digest);
    console.log({signature});
    const toSend = {...tx.raw, Signature: [Buffer.from(signature).toString('base64')]};
    console.log({toSend});
    const result = await wallet.broadcast(Buffer.from(JSON.stringify({tx: toSend})), "https://node.testnet.klever.finance");
    console.log("TXHash:", result.hash());
  }catch(e){
    console.log(e)
  }
}

// get account from API (TODO: move to kos)
function getAccount(address) {
  return fetch(`${API}/address/${address}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
  })
    .then(function(response) {
      if (response.ok) {
        return response.json(); // Parse response as JSON
      }
      throw new Error('Network response was not ok.');
    })
    .then(function(data) {
      // Process the parsed JSON data here
      return data.data.account;
    })
    .catch(function(error) {
      console.log('Error:', error.message);
    });
}
