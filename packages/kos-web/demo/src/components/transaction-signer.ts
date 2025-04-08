import {
  ChainData,
  getSupportedChains,
  toBytes,
  TransactionChainOptions,
  Wallet,
} from "kos";

export class TransactionSigner {
  private container: HTMLElement;
  private wallet: Wallet | null = null;
  private result: HTMLDivElement;
  private chainMap: Map<number, ChainData> = new Map();

  constructor(containerId: string) {
    const container = document.getElementById(containerId);
    if (!container) {
      throw new Error(`Container element with id "${containerId}" not found`);
    }
    this.container = container;
    this.initUI();
    this.result = document.createElement("div");
    this.result.className = "result";
    this.result.style.display = "none";
    this.container.appendChild(this.result);

    this.populateBlockchainSelect();
  }

  private initUI(): void {
    const html = `
        <div class="form-group">
          <label for="private-key-tx">Private Key:</label>
          <input type="text" id="private-key-tx" placeholder="Enter the hexadecimal private key">
        </div>
  
        <div class="form-group">
          <label for="blockchain-tx">Blockchain:</label>
          <select id="blockchain-tx">
            <option value="">Loading blockchains...</option>
          </select>
        </div>
  
        <div class="form-group">
          <label for="tx-type">Transaction Type:</label>
          <select id="tx-type">
            <option value="message">Message</option>
            <option value="transaction">Transaction</option>
          </select>
        </div>
  
        <div class="form-group" id="message-group">
          <label for="message-input">Message:</label>
          <textarea id="message-input" rows="3" placeholder="Enter the message to sign"></textarea>
        </div>
  
        <div class="form-group" id="transaction-group" style="display: none;">
          <label for="transaction-data">Transaction Data (Hex):</label>
          <textarea id="transaction-data" rows="5" placeholder="Enter the transaction data in hexadecimal"></textarea>
  
          <div class="form-group" id="chain-options">
            <label for="chain-option-type">Chain Options:</label>
            <select id="chain-option-type">
              <option value="none">None</option>
              <option value="ethereum">Ethereum</option>
              <option value="bitcoin">Bitcoin</option>
              <option value="cosmos">Cosmos</option>
            </select>
            
            <div id="ethereum-options" style="display: none; margin-top: 10px;">
              <label for="eth-chain-id">Chain ID:</label>
              <input type="number" id="eth-chain-id" value="1">
            </div>
            
            <div id="bitcoin-options" style="display: none; margin-top: 10px;">
              <label for="btc-input-amounts">Input Amounts (comma-separated):</label>
              <input type="text" id="btc-input-amounts" placeholder="1000000, 2000000">
              
              <label for="btc-prev-scripts">Previous Scripts (comma-separated):</label>
              <textarea id="btc-prev-scripts" rows="2" placeholder="script1, script2"></textarea>
            </div>
            
            <div id="cosmos-options" style="display: none; margin-top: 10px;">
              <label for="cosmos-chain-id">Chain ID:</label>
              <input type="text" id="cosmos-chain-id" value="cosmoshub-4">
              
              <label for="cosmos-account-number">Account Number:</label>
              <input type="number" id="cosmos-account-number" value="0">
            </div>
          </div>
        </div>
  
        <button id="load-wallet-btn">Load Wallet</button>
        <button id="sign-btn" disabled>Sign</button>
      `;

    this.container.innerHTML = html;

    // Add event listeners
    this.addEventListeners();
  }

  private populateBlockchainSelect(): void {
    try {
      const blockchainSelect = document.getElementById(
        "blockchain-tx"
      ) as HTMLSelectElement;
      if (!blockchainSelect) return;

      blockchainSelect.innerHTML = "";

      const chains = getSupportedChains();

      chains.forEach((chain) => {
        this.chainMap.set(chain.id, chain);
      });

      chains.sort((a, b) => a.getName().localeCompare(b.getName()));

      chains.forEach((chain) => {
        const option = document.createElement("option");
        option.value = chain.getId().toString();
        option.textContent = `${chain.getName()} (${chain.getSymbol()})`;
        blockchainSelect.appendChild(option);
      });

      // Free the chains after populating the select element
      chains.forEach((chain) => {
        chain.free();
      });
    } catch (error) {
      console.error("Erro ao carregar blockchains:", error);
      const blockchainSelect = document.getElementById(
        "blockchain-tx"
      ) as HTMLSelectElement;
      if (blockchainSelect) {
        blockchainSelect.innerHTML =
          '<option value="">Erro ao carregar blockchains</option>';
      }
    }
  }

  private addEventListeners(): void {
    const txType = document.getElementById("tx-type") as HTMLSelectElement;
    const messageGroup = document.getElementById(
      "message-group"
    ) as HTMLDivElement;
    const transactionGroup = document.getElementById(
      "transaction-group"
    ) as HTMLDivElement;
    const loadWalletBtn = document.getElementById(
      "load-wallet-btn"
    ) as HTMLButtonElement;
    const signBtn = document.getElementById("sign-btn") as HTMLButtonElement;
    const chainOptionType = document.getElementById(
      "chain-option-type"
    ) as HTMLSelectElement;
    const ethereumOptions = document.getElementById(
      "ethereum-options"
    ) as HTMLDivElement;
    const bitcoinOptions = document.getElementById(
      "bitcoin-options"
    ) as HTMLDivElement;
    const cosmosOptions = document.getElementById(
      "cosmos-options"
    ) as HTMLDivElement;

    // Toggle between message and transaction
    txType.addEventListener("change", () => {
      if (txType.value === "message") {
        messageGroup.style.display = "block";
        transactionGroup.style.display = "none";
      } else {
        messageGroup.style.display = "none";
        transactionGroup.style.display = "block";
      }
    });

    // Toggle between chain options
    chainOptionType.addEventListener("change", () => {
      ethereumOptions.style.display = "none";
      bitcoinOptions.style.display = "none";
      cosmosOptions.style.display = "none";

      switch (chainOptionType.value) {
        case "ethereum":
          ethereumOptions.style.display = "block";
          break;
        case "bitcoin":
          bitcoinOptions.style.display = "block";
          break;
        case "cosmos":
          cosmosOptions.style.display = "block";
          break;
      }
    });

    // Load the wallet
    loadWalletBtn.addEventListener("click", () => {
      this.loadWallet();
      signBtn.disabled = false;
    });

    // Sign the message or transaction
    signBtn.addEventListener("click", () => {
      if (txType.value === "message") {
        this.signMessage();
      } else {
        this.signTransaction();
      }
    });
  }

  private loadWallet(): void {
    try {
      const privateKey = (
        document.getElementById("private-key-tx") as HTMLInputElement
      ).value.trim();
      const chainId = parseInt(
        (document.getElementById("blockchain-tx") as HTMLSelectElement).value
      );

      if (!privateKey) {
        throw new Error("Private key is required");
      }

      // Free the previous wallet if it exists
      if (this.wallet) {
        this.wallet.free();
      }

      this.wallet = Wallet.fromPrivateKey(chainId, privateKey);

      this.showSuccess(
        `Wallet successfully loaded! Address: ${this.wallet.getAddress()}`
      );
    } catch (error) {
      this.showError((error as Error).message);
    }
  }

  private signMessage(): void {
    if (!this.wallet) {
      this.showError("Wallet not loaded");
      return;
    }

    try {
      const message = (
        document.getElementById("message-input") as HTMLTextAreaElement
      ).value;
      if (!message) {
        throw new Error("Message is required");
      }

      const messageBytes = toBytes(message);
      const signature = this.wallet.signMessage(messageBytes);

      // Convert to hexadecimal for display
      const hexSignature = Array.from(signature)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      this.showResult(`
          <h3>Message Signature</h3>
          <p><strong>Message:</strong> ${message}</p>
          <p><strong>Signature (hex):</strong> ${hexSignature}</p>
        `);
    } catch (error) {
      this.showError((error as Error).message);
    }
  }

  private signTransaction(): void {
    if (!this.wallet) {
      this.showError("Wallet not loaded");
      return;
    }

    try {
      const txDataHex = (
        document.getElementById("transaction-data") as HTMLTextAreaElement
      ).value.trim();
      if (!txDataHex) {
        throw new Error("Transaction data is required");
      }

      // Convert the hex string to bytes
      const txData = new Uint8Array(
        txDataHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
      );

      // Get chain options, if any
      let chainOptions: TransactionChainOptions | null = null;
      const chainOptionType = (
        document.getElementById("chain-option-type") as HTMLSelectElement
      ).value;

      if (chainOptionType !== "none") {
        chainOptions = this.createChainOptions(chainOptionType);
      }

      const transaction = this.wallet.sign(txData, chainOptions);

      // Convert values to hexadecimal for display
      const rawDataHex = Array.from(transaction.getRawData())
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      const signatureHex = Array.from(transaction.getSignature())
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      const txHashHex = Array.from(transaction.getTxHash())
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      this.showResult(`
          <p><strong>Transaction Hash:</strong> ${txHashHex}</p>
          <p><strong>Signature (hex):</strong> ${signatureHex}</p>
          <p><strong>Raw Data (hex):</strong> ${rawDataHex}</p>
        `);

      // Free the transaction
      transaction.free();

      // Free chain options
      if (chainOptions) {
        chainOptions.free();
      }
    } catch (error) {
      this.showError((error as Error).message);
    }
  }

  private createChainOptions(optionType: string): TransactionChainOptions {
    switch (optionType) {
      case "ethereum": {
        const chainId = parseInt(
          (document.getElementById("eth-chain-id") as HTMLInputElement).value
        );
        return TransactionChainOptions.newEthereumSignOptions(chainId);
      }
      case "bitcoin": {
        const amountsStr = (
          document.getElementById("btc-input-amounts") as HTMLInputElement
        ).value;
        const scriptsStr = (
          document.getElementById("btc-prev-scripts") as HTMLTextAreaElement
        ).value;

        const amounts = amountsStr.split(",").map((a) => BigInt(a.trim()));
        const scripts = scriptsStr.split(",").map((s) => s.trim());

        // Create array of BigUint64Array
        const inputAmounts = new BigUint64Array(amounts.length);
        amounts.forEach((amount, index) => {
          inputAmounts[index] = amount;
        });

        return TransactionChainOptions.newBitcoinSignOptions(
          inputAmounts,
          scripts
        );
      }
      case "cosmos": {
        const chainId = (
          document.getElementById("cosmos-chain-id") as HTMLInputElement
        ).value;
        const accountNumber = BigInt(
          (document.getElementById("cosmos-account-number") as HTMLInputElement)
            .value
        );
        return TransactionChainOptions.newCosmosSignOptions(
          chainId,
          accountNumber
        );
      }
      default:
        throw new Error(`Unsupported chain option type: ${optionType}`);
    }
  }

  private showResult(html: string): void {
    this.result.innerHTML = html;
    this.result.style.display = "flex";
  }

  private showError(message: string): void {
    this.result.innerHTML = `<div class="error">${message}</div>`;
    this.result.style.display = "flex";
  }

  private showSuccess(message: string): void {
    this.result.innerHTML = `<div class="success">${message}</div>`;
    this.result.style.display = "flex";
  }
}
