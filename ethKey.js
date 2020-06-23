import Web3 from "web3";

const web3 = new Web3();

// 16진수를 처리해야하므로 0x를 붙여야 함.
const privateKey = "0xb9ba75fbaeb8b9014e76bfd3de66a98d1c650ea2ec26801d896d16be1e20c294" 
const account = web3.eth.accounts.privateKeyToAccount(privateKey);

console.log(account)
