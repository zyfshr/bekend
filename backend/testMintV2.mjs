import { Metaplex } from '@metaplex-foundation/js';
import { Connection, clusterApiUrl } from '@solana/web3.js';

const connection = new Connection(clusterApiUrl('devnet'));
const metaplex = new Metaplex(connection);

console.log('metaplex.candyMachines:', typeof metaplex.candyMachines);
console.log('metaplex.candyMachines().mintV2:', typeof metaplex.candyMachines().mintV2);
