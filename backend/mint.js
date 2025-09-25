import dotenv from 'dotenv';
dotenv.config();

import { readFileSync } from 'fs';
import { Connection, Keypair, clusterApiUrl, PublicKey } from '@solana/web3.js';
import { Metaplex, keypairIdentity } from '@metaplex-foundation/js';

async function main() {
  const walletKeypair = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync(process.env.WALLET_PATH, 'utf-8')))
  );
  console.log('Wallet PublicKey:', walletKeypair.publicKey.toBase58());

  const connection = new Connection(clusterApiUrl('devnet'), 'confirmed');
  console.log('Connected to Solana cluster:', connection.rpcEndpoint);

  const metaplex = Metaplex.make(connection).use(keypairIdentity(walletKeypair));

  try {
    const candyMachineAddress = new PublicKey(process.env.CANDY_MACHINE_ID);
    console.log('Loading Candy Machine:', candyMachineAddress.toBase58());

    const candyMachine = await metaplex.candyMachines().findByAddress({ address: candyMachineAddress });
    console.log('Candy Machine data loaded.');

    const { nft } = await metaplex.candyMachines().mint({
      candyMachine,
      payer: walletKeypair,
      buyer: walletKeypair,
    });

    console.log('🎉 NFT minted successfully!');
    console.log('Mint Address:', nft.address.toBase58());
  } catch (error) {
    console.error('Mint failed:', error);
  }
}

main();
