import { CryptographyDemo } from "./components/cryptography-demo";
import { TransactionSigner } from "./components/transaction-signer";
import { WalletGenerator } from "./components/wallet-generator";
import "./style.css";

// Initialize components
try {
  console.log("starting");
  new WalletGenerator("wallet-generator");
  new TransactionSigner("transaction-signer");
  new CryptographyDemo("cryptography-demo");
} catch (error) {
  console.error("Error initializing the demonstration:", error);
}
