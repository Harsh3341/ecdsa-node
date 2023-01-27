const secp = require("ethereum-cryptography/secp256k1");
const { toHex } = require("ethereum-cryptography/utils");
const { keccak256 } = require("ethereum-cryptography/keccak");

const privateKey = secp.utils.randomPrivateKey();
const publicKey = secp.getPublicKey(privateKey);

const getAddress = (publicKey) => {
  const pubKeyWithoutFirstByte = publicKey.slice(1);
  const hash = keccak256(pubKeyWithoutFirstByte);
  const addressHex = hash.slice(-20);

  const address = `0x${toHex(addressHex)}`;

  return address;
};

const address = getAddress(publicKey);
console.log("Private key:", toHex(privateKey));
console.log("Public key:", toHex(publicKey));
console.log("Address:", address);
