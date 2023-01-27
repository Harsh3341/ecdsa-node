const express = require("express");
const app = express();
const cors = require("cors");
const secp = require("ethereum-cryptography/secp256k1");
const { toHex } = require("ethereum-cryptography/utils");
const { keccak256 } = require("ethereum-cryptography/keccak");
const { utf8ToBytes } = require("ethereum-cryptography/utils");
const port = 3042;

app.use(cors());
app.use(express.json());

const balances = {
  "0x258f2ae05427f95db3cd7a8d23dedc0b3ad8f95d": 100,
  /* Private key: 4fd4907be7c914b32c318b14af504557543759fe1a6583f6a6bc56421e700d42
  Public key: 043857c4aadb9b5acce4b0a1f772f32da36ff243d2c6fb41fe863dc56c87de8424241e0f07d3894b33361d41732cbcdcf7c1fbbc596ceedb57b1d30f3d1a61b65b
  Address: 0x258f2ae05427f95db3cd7a8d23dedc0b3ad8f95d */

  "0xe035955d2ddd9589259d122f54e550e619d5769c": 65,
  /* Private key: e83eba99ae6a329ea7136484f5fbe34ba8dcd0478bd37e7f84fa1c3e7a2d81e0
  Public key: 04ae94a5345b90b5a977d79e5a5255f5a1f2259a5dde1ba218ccca8833c81165ecef2ade6b87c76a3ddad4486a57149e538382973d818ebb6d1a3684c9b6719fe3
  Address: 0xe035955d2ddd9589259d122f54e550e619d5769c */

  "0xe175fbba6df63afdcb2fc3457e61a543d2e0cb58": 70,
  /* Private key: c445f3f7ff7ca97a79d9de46fce54329981468b0ac05cbb193b7df4a07266ff9
  Public key: 04c6c4164b5ebf27e178d7f93991ea2d05eb5f8995e5018a8695695a690e283c41a8e3e24dea80a6374dfddd3bcfd823bde34a482d312cb02f85cedde7448bf04b
  Address: 0xe175fbba6df63afdcb2fc3457e61a543d2e0cb58 */
};

const convertObjectToArray = (obj) => {
  let arr = [];
  const keys = Object.keys(obj);
  for (let i = 0; i < keys.length; i++) {
    arr.push(obj[keys[i]]);
  }
  return new Uint8Array(arr);
};

app.get("/balance/:address", (req, res) => {
  const { address } = req.params;

  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post("/send", (req, res) => {
  const { message, messageHash, signature } = req.body;
  const { sender, amount, recipient, senderPublicKey } = message;
  const [sig, recoveryBit] = signature;

  setInitialBalance(sender);
  setInitialBalance(recipient);

  let messageHashArray = convertObjectToArray(messageHash);
  let sigArray = convertObjectToArray(sig);

  const messageHashToString = JSON.stringify(messageHashArray);
  const messageToString = JSON.stringify(
    keccak256(utf8ToBytes(JSON.stringify(message)))
  );

  if (messageHashToString !== messageToString) {
    res.status(400).send({ message: "Message hash is not correct!" });
    return;
  }

  const recoveredPublicKey = secp.recoverPublicKey(
    messageHashArray,
    sigArray,
    recoveryBit
  );

  if (senderPublicKey !== toHex(recoveredPublicKey)) {
    res.status(400).send({ message: "Public key is not correct!" });
    return;
  }

  const isSignatureValid = secp.verify(
    sigArray,
    messageHashArray,
    toHex(recoveredPublicKey),
    { strict: true }
  );

  if (!isSignatureValid) {
    res.status(400).send({ message: "Signature is not valid!" });
    return;
  }

  if (balances[sender] < amount) {
    res.status(400).send({ message: "Not enough funds!" });
  } else {
    balances[sender] -= amount;
    balances[recipient] += amount;
    res.send({ balance: balances[sender] });
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});

function setInitialBalance(address) {
  if (!balances[address]) {
    balances[address] = 0;
  }
}
