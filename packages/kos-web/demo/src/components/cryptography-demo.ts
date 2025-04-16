import { decrypt, encrypt, fromPem, toBytes, toPem, toString } from "kos";

export class CryptographyDemo {
  private container: HTMLElement;
  private result: HTMLDivElement;

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
  }

  private initUI(): void {
    const html = `
        <div class="form-group">
          <label for="crypto-action">Action:</label>
          <select id="crypto-action">
            <option value="encrypt">Encrypt</option>
            <option value="decrypt">Decrypt</option>
            <option value="to-pem">Convert to PEM</option>
            <option value="from-pem">Convert from PEM</option>
          </select>
        </div>
  
        <div class="form-group" id="data-input-group">
          <label for="data-input">Data:</label>
          <textarea id="data-input" rows="4" placeholder="Enter the data to encrypt/decrypt"></textarea>
        </div>
  
        <div class="form-group" id="password-group">
          <label for="password-input">Password:</label>
          <input type="password" id="password-input" placeholder="Enter the password">
        </div>
  
        <div class="form-group" id="pem-tag-group" style="display: none;">
          <label for="pem-tag">PEM Tag:</label>
          <input type="text" id="pem-tag" value="ENCRYPTED DATA" placeholder="Ex: ENCRYPTED DATA">
        </div>
  
        <button id="execute-crypto">Execute</button>
      `;

    this.container.innerHTML = html;

    // Add event listeners
    this.addEventListeners();
  }

  private addEventListeners(): void {
    const cryptoAction = document.getElementById(
      "crypto-action"
    ) as HTMLSelectElement;
    const pemTagGroup = document.getElementById(
      "pem-tag-group"
    ) as HTMLDivElement;
    const dataInputLabel = document.querySelector(
      "#data-input-group label"
    ) as HTMLLabelElement;
    const executeBtn = document.getElementById(
      "execute-crypto"
    ) as HTMLButtonElement;

    // Toggle between encryption options
    cryptoAction.addEventListener("change", () => {
      switch (cryptoAction.value) {
        case "encrypt":
          dataInputLabel.textContent = "Data:";
          pemTagGroup.style.display = "none";
          break;
        case "decrypt":
          dataInputLabel.textContent = "Data (Hex):";
          pemTagGroup.style.display = "none";
          break;
        case "to-pem":
          dataInputLabel.textContent = "Data (Hex):";
          pemTagGroup.style.display = "block";
          break;
        case "from-pem":
          dataInputLabel.textContent = "PEM Data:";
          pemTagGroup.style.display = "none";
          break;
      }
    });

    // Execute the cryptography action
    executeBtn.addEventListener("click", () => {
      this.executeCryptoAction();
    });
  }

  private executeCryptoAction(): void {
    try {
      const action = (
        document.getElementById("crypto-action") as HTMLSelectElement
      ).value;
      const inputData = (
        document.getElementById("data-input") as HTMLTextAreaElement
      ).value.trim();
      const password = (
        document.getElementById("password-input") as HTMLInputElement
      ).value;

      if (!inputData) {
        throw new Error("Input data is required");
      }

      switch (action) {
        case "encrypt":
          this.encryptData(inputData, password);
          break;
        case "decrypt":
          this.decryptData(inputData, password);
          break;
        case "to-pem":
          this.convertToPem(inputData);
          break;
        case "from-pem":
          this.convertFromPem(inputData, password);
          break;
      }
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

  private encryptData(data: string, password: string): void {
    if (!password) {
      throw new Error("Password is required for encryption");
    }

    const dataBytes = toBytes(data);
    const encryptedBytes = encrypt(dataBytes, password);

    // Convert encrypted bytes to hexadecimal for display
    const hexEncrypted = Array.from(encryptedBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    this.showResult(`
        <h3>Encrypted Data</h3>
        <p><strong>Original Data:</strong> ${data}</p>
        <p><strong>Encrypted Data (hex):</strong> ${hexEncrypted}</p>
      `);
  }

  private decryptData(hexData: string, password: string): void {
    if (!password) {
      throw new Error("Password is required for decryption");
    }

    // Convert the hex string to bytes
    try {
      const encryptedBytes = new Uint8Array(
        hexData.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
      );
      const decryptedBytes = decrypt(encryptedBytes, password);
      const decryptedText = toString(decryptedBytes);

      this.showResult(`
          <h3>Decrypted Data</h3>
          <p><strong>Encrypted Data (hex):</strong> ${hexData}</p>
          <p><strong>Decrypted Data:</strong> ${decryptedText}</p>
        `);
    } catch (e) {
      throw new Error(`Error converting hex to bytes: ${e}`);
    }
  }

  private convertToPem(hexData: string): void {
    // Convert the hex string to bytes
    try {
      const dataBytes = new Uint8Array(
        hexData.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
      );
      const tag = (
        document.getElementById("pem-tag") as HTMLInputElement
      ).value.trim();

      if (!tag) {
        throw new Error("PEM tag is required");
      }

      const pemData = toPem(tag, dataBytes);

      this.showResult(`
          <h3>Conversion to PEM</h3>
          <p><strong>Original Data (hex):</strong> ${hexData}</p>
          <p><strong>PEM Format:</strong></p>
          <pre>${pemData}</pre>
        `);
    } catch (e) {
      throw new Error(`Error converting hex to bytes: ${e}`);
    }
  }

  private convertFromPem(pemData: string, password: string): void {
    try {
      if (!password) {
        throw new Error("Password is required for PEM decryption");
      }

      const bytes = fromPem(pemData, password);

      // Convert bytes to hexadecimal for display
      const hexData = Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      this.showResult(`
          <h3>Conversion from PEM</h3>
          <p><strong>Original PEM Data:</strong></p>
          <pre>${pemData}</pre>
          <p><strong>Converted Data (hex):</strong> ${hexData}</p>
        `);
    } catch (e) {
      throw new Error(`Error converting from PEM: ${e}`);
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
}
