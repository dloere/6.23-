import key from "./key.js";
import secp256k1 from "secp256k1";
import crypto from "crypto";
import createkeccakHash from "keccak";
import web3 from "web3"


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

//이더리움 사인에서는 message를 바로 해쉬하지 않고 여러가지를 추가한 후에 해쉬함. 
function ethSign(message, privateKey){
    const prefix = "\x19Ethereum Signed Message:\n" + message.length;
    const buffer = Buffer.from(prefix + message);
    const hash = createkeccakHash("keccak256").update(buffer).digest();
    return secp256k1.ecdsaSign(hash, privateKey);//개인키로 암호화 해서 서명
}

// 이더리움은 공개키가 아니라 주소를 복원함.
function ethRecover(message, signature) {
    const prefix = "\x19Ethereum Signed Message:\n" + message.length;
    const buffer = Buffer.from(prefix + message);
    const hash = createkeccakHash("keccak256").update(buffer).digest();
    const publicKey = Buffer.from(secp256k1.ecdsaRecover(signature.signature ,signature.recid, hash, false));
    // 공개키를 알아냄.
    const address = key.createAddress(publicKey); 
    return key.toChecksumAddress(address); //이더리움은 주소를 복원
}


const privateKey = key.createPrivatekey();
const address = key.privateKeyToAddress(privateKey);
console.log("sender address", address);

const signature =  ethSign("hello Blockchain", privateKey);
const recoveredAddress = ethRecover("hello Blockchain", signature)
console.log("recovered address : ", recoveredAddress);

