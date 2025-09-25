import fetch from 'node-fetch';
import { readFileSync } from 'fs';
import { Keypair } from '@solana/web3.js';
import dotenv from 'dotenv';

dotenv.config();

const SHYFT_API_KEY = process.env.SHYFT_API_KEY;
const WALLET_PATH = process.env.WALLET_PATH;            // Candy Machine authority wallet
const CANDY_MACHINE_ID = process.env.CANDY_MACHINE_ID;  // 你的 Candy Machine 地址
const NETWORK = 'devnet'; // 或 'mainnet-beta'

async function onUserClaim() {
  const secret = JSON.parse(readFileSync(WALLET_PATH, 'utf8'));
  const keypair = Keypair.fromSecretKey(Uint8Array.from(secret));
  const walletAddress = keypair.publicKey.toBase58();

  const resp = await fetch('https://api.shyft.to/sol/v1/nft/candy-machine/mint', {
    method: 'POST',
    headers: {
      'x-api-key': SHYFT_API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      network: NETWORK,
      wallet: walletAddress,
      candyMachine: CANDY_MACHINE_ID
    })
  });

  const result = await resp.json();
  if (result.success) {
    console.log('✅ Mint 成功，交易签名：', result.data.transactionSignature);
  } else {
    console.error('❌ Mint 失败：', result.error);
  }
}

onUserClaim();
