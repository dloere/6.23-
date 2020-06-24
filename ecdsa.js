import key from "./key.js";
import secp256k1 from "secp256k1";
import crypto from "crypto";



//secp256k로 서명을 하려면 메세지를 고정된 32바이트로 만들어야함. ==> 해쉬함수로 만든다. (SHA256, Keccak256) 256비트는 32바이트
//SHA256은 오래되었으나 가속방법이 많이 연구되어 빠름. 
// keccak은 최신에 나와서 개선점이많으나 느림.

function sign(message, privateKey) {
    const hash = crypto.createHash("sha256").update(message).digest(); // 해쉬함수로 만들기
    return secp256k1.ecdsaSign(hash, privateKey); // 사인
}

function recover(message, signature){
    const hash = crypto.createHash("sha256").update(message).digest();
    return Buffer.from(secp256k1.ecdsaRecover(signature.signature, signature.recid, hash))
}

const privateKey = key.createPrivatekey();
const publicKey = key.createPublicKey2(privateKey);
console.log("public key : ", publicKey. toString("hex"));
const message = "hello blockchain"
console.log(message)


// const {signature2 , recoveryId } = sign("hello blockchain", privateKey);
const signature = sign(message, privateKey);
const recoveredkey = recover(message, signature);
console.log(signature)
console.log("recoveredKey : ", recoveredkey)
