import crypto from "crypto"; // es6문법
import secp256k1 from "secp256k1";
import createKeccakHash from "keccak";
import Mnemonic from "bitcore-mnemonic";


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




// 이더리움 주소는 압축되지 않은 공개키가 필요하다.
// 공개키생성의 기본설정은 true임. 
// 억지로 false를 넣어주면 압축되지 않은 공개키를 얻을 수 있다. 압축되지 않은 공개키는 04로 시작
function createPublicKey2(privateKey, compressed) {
    return Buffer.from(secp256k1.publicKeyCreate(privateKey, compressed));
}



//keccak256 .. 256은 32바이트 32바이트는 16진수로 64글자.
//이중에서 주소는 앞에 24개를 버리고 40개를 취한다.
function createAddress(publicKey) {
    // 참고로 64개중에서 앞에 04는 당연히 잘라야함.(slice(1)) 16진수로 처리하기 전이므로 1개 1byte자를시 2개가 잘림
    const hash = createKeccakHash("keccak256").update(publicKey.slice(1)).digest("hex"); //16진수 변환
    //앞에 0x 붙여야함. 앞에 24개를 버리고 40개를 취해야함. 
    return "0x" + hash.slice(24);
}





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



function privateKeyToAddress(privateKey) {
  const publicKey = createPublicKey(privateKey)
  const address = createAddress(publicKey)
  return toChecksumAddress(address)
}

// 무작위 12개 단어 생성.
// 12 ~ 24 단어까지가능
// 12개 단어는 128bits = 16bytes && 24개 단어는 256bits = 32bytes
// mnemonic를 사용하려면 단어가 아니라 bit를 입력해줘야함.
function createMnemonic(wordsCount = 12) {
  if(wordsCount < 12 || wordsCount >24 || wordsCount % 3 == !0) {
    throw new Error("invalid number of words");
  }
  const entropy = (16 + (wordsCount - 12) / 3 * 4) * 8 ; // bit로 변환
  return new Mnemonic(entropy) 
}

function mneMonicToPrivateKey(mnemonic) {
  const privateKey = mnemonic.toHDPrivateKey().derive("m/44'/60'/0'/0/0").privateKey;
  // mnemonic를 갖고 이더리움 개인키(60)를 생성.
  return Buffer.from(privateKey.toString(), "hex"); // buffer로 바꿔서 저장.
}

const mnemonic = createMnemonic();
console.log("mnemonic : ", mnemonic.toString());

const privateKey = mneMonicToPrivateKey(mnemonic);
console.log("개인키 : ", privateKey.toString("hex") );

const address = privateKeyToAddress(privateKey);
console.log("주소 :", address);

