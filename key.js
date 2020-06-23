// const crypto = require("crypto"); 

import crypto from "crypto"; // es6문법
import secp256k1 from "secp256k1";
import createKeccakHash from "keccak";

function createPrivatekey() {
    let privateKey; 
    do { 
        privateKey = crypto.randomBytes(32); // 개인키는 32byte
    } while(secp256k1.privateKeyVerify(privateKey) === false);
    return privateKey;
}


function createPublicKey(privateKey) {
    return Buffer.from(secp256k1.publicKeyCreate(privateKey));
}

let privateKey = createPrivatekey();
console.log("개인키 : " + privateKey.toString("hex")); // 32byte
console.log("압축 된 공개키 : " + createPublicKey(privateKey).toString("hex"));//32bytes+1bytes
// 압축되지 않은 공개키는 64byte 이경우는 압축된 공개키.
// 압축된 공개키의 경우 타원곡선 x좌표기준으로 y좌표가 위에 있냐 아래있냐를 표시함.
// 맨 앞에 02 03으로 확인. 그래서 1byte가 많음 1byte가 2개의 숫자를 표시.


// 이더리움 주소는 압축되지 않은 공개키가 필요하다.
// 공개키생성의 기본설정은 true임. 
// 억지로 false를 넣어주면 압축되지 않은 공개키를 얻을 수 있다. 압축되지 않은 공개키는 04로 시작
function createPublicKey2(privateKey, compressed) {
    return Buffer.from(secp256k1.publicKeyCreate(privateKey, compressed));
}

console.log("압축 안 된 공개키 : " + createPublicKey2(privateKey, false).toString("hex"));


//keccak256 .. 256은 32바이트 32바이트는 16진수로 64글자.
//이중에서 주소는 앞에 24개를 버리고 40개를 취한다.

function createAddress(publicKey) {
    // 참고로 64개중에서 앞에 04는 당연히 잘라야함.(slice(1)) 16진수로 처리하기 전이므로 1개 1byte자를시 2개가 잘림
    const hash = createKeccakHash("keccak256").update(publicKey.slice(1)).digest("hex"); //16진수 변환
    //앞에 0x 붙여야함. 앞에 24개를 버리고 40개를 취해야함. 
    return "0x" + hash.slice(24);
}

console.log("Address : ", createAddress(createPublicKey(privateKey)));



// 변수생성 let과 const의 차이. 
// let은 변수를 자주 바꿀 때 const는 한 번 정하면 안 바꿀 경우


const real_privateKey = Buffer.from("b9ba75fbaeb8b9014e76bfd3de66a98d1c650ea2ec26801d896d16be1e20c294", "hex")

const real_publicKey = createPublicKey2(real_privateKey, false); // 압축안된걸로

const real_address = createAddress(real_publicKey);

console.log("실제 개인키로 뽑은 주소 : ", real_address);


const usermake_privateKey = Buffer.from("000000000000000000000000000000000000000000000000000000000000270f", "hex")

console.log("유저가 만든 키로만든 주소 :", createAddress(createPublicKey2(usermake_privateKey, false)))



function toChecksumAddress (address) {
    address = address.toLowerCase().replace('0x', '')
    var hash = createKeccakHash('keccak256').update(address).digest('hex')
    var ret = '0x'
  
    for (var i = 0; i < address.length; i++) {
      if (parseInt(hash[i], 16) >= 8) {
        ret += address[i].toUpperCase()
      } else {
        ret += address[i]
      }
    }
  
    return ret
  }


const checksumAddress = toChecksumAddress(real_address);

console.log("실제 주소 : ", real_address);
console.log("주소 체크 :" , checksumAddress); // 이더리움 대소문자 규칙에 맞게 