import {
  AccountType,
  ChainData,
  generateMnemonicPhrase,
  getSupportedChains,
  isChainSupported,
  PathOptions,
  Wallet,
} from "kos";

export class WalletGenerator {
  private container: HTMLElement;
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
        <label for="wallet-type">Wallet Type:</label>
        <select id="wallet-type">
          <option value="mnemonic">Mnemonic</option>
          <option value="private-key">Private Key</option>
        </select>
      </div>

      <div class="form-group" id="mnemonic-options">
        <label for="mnemonic-words">Number of Words:</label>
        <select id="mnemonic-words">
          <option value="12">12 words</option>
          <option value="24">24 words</option>
        </select>

        <button id="generate-mnemonic">Generate Mnemonic</button>

        <div class="form-group" id="mnemonic-input-group" style="display: none;">
          <label for="mnemonic-input">Mnemonic:</label>
          <textarea id="mnemonic-input" rows="3" placeholder="Enter mnemonic words separated by space"></textarea>
        </div>

        <div class="form-group">
          <label for="derivation-path">Derivation Path:</label>
          <input type="text" id="derivation-path" value="m/44'/0'/0'/0/0" placeholder="m/44'/0'/0'/0/0">
        </div>

        <div class="form-group" id="mnemonic-index-group">
          <label for="use-index">Use Index:</label>
          <input type="checkbox" id="use-index">
          
          <div id="index-options" style="display: none; margin-top: 10px;">
            <label for="wallet-index">Index:</label>
            <input type="number" id="wallet-index" value="0" min="0">
            
            <label for="use-legacy">
              <input type="checkbox" id="use-legacy"> Use Legacy
            </label>
          </div>
        </div>
      </div>

      <div class="form-group" id="private-key-group" style="display: none;">
        <label for="private-key-input">Private Key:</label>
        <textarea id="private-key-input" rows="3" placeholder="Enter the hexadecimal private key"></textarea>
      </div>

      <div class="form-group">
        <label for="blockchain">Blockchain:</label>
        <select id="blockchain">
          <option value="">Loading blockchains...</option>
        </select>
      </div>

      <button id="create-wallet">Create Wallet</button>
    `;

    this.container.innerHTML = html;

    // Add event listeners
    this.addEventListeners();
  }

  private populateBlockchainSelect(): void {
    try {
      const blockchainSelect = document.getElementById(
        "blockchain"
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

      chains.forEach((chain) => {
        chain.free();
      });
    } catch (error) {
      console.error(error);
      const blockchainSelect = document.getElementById(
        "blockchain"
      ) as HTMLSelectElement;
      if (blockchainSelect) {
        blockchainSelect.innerHTML =
          '<option value="">Error while loading blockchains</option>';
      }
    }
  }

  private addEventListeners(): void {
    const walletType = document.getElementById(
      "wallet-type"
    ) as HTMLSelectElement;
    const mnemonicOptions = document.getElementById(
      "mnemonic-options"
    ) as HTMLDivElement;
    const privateKeyGroup = document.getElementById(
      "private-key-group"
    ) as HTMLDivElement;
    const generateMnemonicBtn = document.getElementById(
      "generate-mnemonic"
    ) as HTMLButtonElement;
    const mnemonicInputGroup = document.getElementById(
      "mnemonic-input-group"
    ) as HTMLDivElement;
    const mnemonicInput = document.getElementById(
      "mnemonic-input"
    ) as HTMLTextAreaElement;
    const useIndexCheckbox = document.getElementById(
      "use-index"
    ) as HTMLInputElement;
    const indexOptions = document.getElementById(
      "index-options"
    ) as HTMLDivElement;
    const createWalletBtn = document.getElementById(
      "create-wallet"
    ) as HTMLButtonElement;

    // Toggle wallet options
    walletType.addEventListener("change", () => {
      if (walletType.value === "mnemonic") {
        mnemonicOptions.style.display = "block";
        privateKeyGroup.style.display = "none";
      } else {
        mnemonicOptions.style.display = "none";
        privateKeyGroup.style.display = "block";
      }
    });

    // Generate a new mnemonic
    generateMnemonicBtn.addEventListener("click", () => {
      const wordCount = parseInt(
        (document.getElementById("mnemonic-words") as HTMLSelectElement).value
      );
      const mnemonic = generateMnemonicPhrase(wordCount);
      mnemonicInput.value = mnemonic;
      mnemonicInputGroup.style.display = "block";
    });

    // Toggle index options
    useIndexCheckbox.addEventListener("change", () => {
      indexOptions.style.display = useIndexCheckbox.checked ? "block" : "none";
    });

    // Create the wallet
    createWalletBtn.addEventListener("click", () => {
      this.createWallet();
    });
  }

  private createWallet(): void {
    try {
      const walletType = (
        document.getElementById("wallet-type") as HTMLSelectElement
      ).value;
      const chainId = parseInt(
        (document.getElementById("blockchain") as HTMLSelectElement).value
      );

      if (!isChainSupported(chainId)) {
        throw new Error(`Blockchain with ID ${chainId} is not supported`);
      }

      let wallet: Wallet;

      if (walletType === "mnemonic") {
        const mnemonic = (
          document.getElementById("mnemonic-input") as HTMLTextAreaElement
        ).value.trim();
        if (!mnemonic) {
          throw new Error("Mnemonic is required");
        }

        const useIndex = (
          document.getElementById("use-index") as HTMLInputElement
        ).checked;

        if (useIndex) {
          const index = parseInt(
            (document.getElementById("wallet-index") as HTMLInputElement).value
          );
          const useLegacy = (
            document.getElementById("use-legacy") as HTMLInputElement
          ).checked;

          const pathOptions = PathOptions.new(index);
          pathOptions.setLegacy(useLegacy);

          wallet = Wallet.fromMnemonicIndex(chainId, mnemonic, pathOptions);
        } else {
          const path = (
            document.getElementById("derivation-path") as HTMLInputElement
          ).value;
          wallet = Wallet.fromMnemonic(chainId, mnemonic, path);
        }
      } else {
        const privateKey = (
          document.getElementById("private-key-input") as HTMLTextAreaElement
        ).value.trim();
        if (!privateKey) {
          throw new Error("Private key is required");
        }
        wallet = Wallet.fromPrivateKey(chainId, privateKey);
      }

      this.displayWalletInfo(wallet);

      // Free resources
      wallet.free();
    } catch (error) {
      if (error instanceof Error) {
        this.showError(error.message);
        return;
      }
      if (typeof error === "string") {
        this.showError(error);
        return;
      }

      this.showError("An unknown error occurred");
    }
  }

  private displayWalletInfo(wallet: Wallet): void {
    const accountTypeLabels = {
      [AccountType.Mnemonic]: "Mnemonic",
      [AccountType.PrivateKey]: "Private Key",
      [AccountType.KleverSafe]: "KleverSafe",
      [AccountType.ReadOnly]: "Read Only",
    };

    let info = `<h3>Wallet Information</h3>
      <p><strong>Type:</strong> ${
        accountTypeLabels[wallet.getAccountType()]
      }</p>
      <p><strong>Address:</strong> ${wallet.getAddress()}</p>
      <p><strong>Public Key:</strong> ${wallet.getPublicKey()}</p>
      <p><strong>Private Key:</strong> ${wallet.getPrivateKey()}</p>
      `;

    this.result.innerHTML = info;
    this.result.style.display = "flex";
  }

  private showError(message: string): void {
    this.result.innerHTML = `<div class="error">${message}</div>`;
    this.result.style.display = "flex";
  }
}
