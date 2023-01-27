import { useState } from "react";
import server from "./server";
import * as secp from "ethereum-cryptography/secp256k1";
import { keccak256 } from "ethereum-cryptography/keccak";
import { utf8ToBytes } from "ethereum-cryptography/utils";
import { toHex } from "ethereum-cryptography/utils";

function Transfer({ address, setBalance }) {
  const [sendAmount, setSendAmount] = useState("");
  const [recipient, setRecipient] = useState("");
  const [privateKey, setPrivateKey] = useState("");

  const setValue = (setter) => (evt) => setter(evt.target.value);

  const hashMessage = async (message) => {
    const messageToBytes = utf8ToBytes(message);
    return keccak256(messageToBytes);
  };

  async function transfer(evt) {
    evt.preventDefault();

    const publicKey = await secp.getPublicKey(privateKey);

    const message = {
      sender: address,
      amount: parseInt(sendAmount),
      recipient,
      senderPublicKey: toHex(publicKey),
    };

    const messageToString = JSON.stringify(message);
    const messageHash = await hashMessage(messageToString);
    const signature = await secp.sign(messageHash, privateKey, {
      recovered: true,
    });

    const response = await server.post("/send", {
      message,
      messageHash,
      signature,
    });

    if (response.data.balance) {
      setBalance(response.data.balance);
    } else {
      alert(response.data.message);
    }
  }

  return (
    <form className="container transfer" onSubmit={transfer}>
      <h1>Send Transaction</h1>

      <label>
        Send Amount
        <input
          placeholder="1, 2, 3..."
          value={sendAmount}
          onChange={setValue(setSendAmount)}
        ></input>
      </label>

      <label>
        Recipient
        <input
          placeholder="Type an address, for example: 0x2"
          value={recipient}
          onChange={setValue(setRecipient)}
        ></input>
      </label>

      <label>
        Private Key
        <input
          placeholder="Enter your private keys"
          value={privateKey}
          onChange={setValue(setPrivateKey)}
        ></input>
      </label>

      <input type="submit" className="button" value="Transfer" />
    </form>
  );
}

export default Transfer;
