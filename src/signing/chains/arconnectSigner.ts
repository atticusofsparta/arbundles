import type { Signer } from "..";
import { SignatureConfig, SIG_CONFIG } from "../../constants";
import type Arweave from "@irys/arweave";
import base64url from "base64url";
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import type * as _ from "arconnect";
import { getCryptoDriver } from "$/utils";
import type { Transaction } from "$/utils";
import type { DataItem } from "../../DataItem";

export default class InjectedArweaveSigner implements Signer {
  private signer: Window["arweaveWallet"];
  public publicKey: Buffer;
  readonly ownerLength: number = SIG_CONFIG[SignatureConfig.ARWEAVE].pubLength;
  readonly signatureLength: number = SIG_CONFIG[SignatureConfig.ARWEAVE].sigLength;
  readonly signatureType: SignatureConfig = SignatureConfig.ARWEAVE;
  protected arweave: Arweave;
  constructor(windowArweaveWallet: Window["arweaveWallet"], arweave: Arweave) {
    this.signer = windowArweaveWallet;
    this.arweave = arweave;
  }

  async setPublicKey(): Promise<void> {
    const arOwner = await this.signer.getActivePublicKey();
    this.publicKey = base64url.toBuffer(arOwner);
  }
  /**
   * @param message signature data to sign (not currently used)
   * @param {@type {dataItem?: DataItem, transaction?: Transaction}} the data item to sign
   * @returns signatureBytes - the signature in bytes which is then processed as the signature and id
   */
  // eslint-disable-next-line
  // @ts-ignore
  async sign(message: unknown, item: { dataItem: DataItem } | { transaction: Transaction }): Promise<Uint8Array> {
    if (!this.publicKey) {
      await this.setPublicKey();
    }

    // const algorithm = {
    //   name: "RSA-PSS",
    //   saltLength: 32,
    // };
    // DEPRECATED
    // const signature = await this.signer.signature(message, algorithm);

    let signedItem;
    if ("dataItem" in item) {
      signedItem = await this.signer.signDataItem(item.dataItem);
    } else if ("transaction" in item) {
      signedItem = await this.signer.sign(item.transaction);
    } else {
      throw new Error("Invalid item type, must provide either a DataItem or a Transaction");
    }

    if (!signedItem ?? !signedItem.signature) {
      throw new Error("Failed to sign item");
    }

    const buf = new Uint8Array(Object.values(signedItem.signature).map((v: string | number) => +v));
    return buf;
  }

  static async verify(pk: string, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    return await getCryptoDriver().verify(pk, message, signature);
  }
}
