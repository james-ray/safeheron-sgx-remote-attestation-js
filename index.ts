import * as express from 'express';
import { Request, Response } from 'express';
import BN from 'bn.js';
import HashUtils, { RemoteAttestor } from './lib';
import * as fs from 'fs';
import * as crypto from 'crypto';

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json()); // Middleware to parse JSON bodies

export {RemoteAttestor}

app.post('/webhook', async (req: Request, res: Response) => {
    console.time('attestation');
    try {
        // Log the entire request body for debugging
        console.log('Request body:', req.body);
        const { pubkey_list_hash, rsa_public_key, tee_report } = req.body;
        const { combinedHash, encodedCombinedHash } = HashUtils.combineHashes(pubkey_list_hash, rsa_public_key, tee_report);

        // Add the hashes to the request body
        req.body.combinedHash = combinedHash;
        req.body.encodedCombinedHash = encodedCombinedHash;

        // Print out the hashes
        console.log('Combined Hash:', combinedHash);
        console.log('Encoded Combined Hash:', encodedCombinedHash);
        console.log(req.body);

        res.json({ success: true, combinedHash, encodedCombinedHash });
    } catch (error) {
        console.error('Error during logging:', error);
        res.status(500).send(`Logging failed: ${(error as Error).message}`);
    }
    console.timeEnd('attestation');
});

// Modify the handler for /decrypt-key-shard
app.post('/decrypt-key-shard', async (req: Request, res: Response) => {
    console.time('decrypt-key-shard');
    try {
        const sgx_root_cert = fs.readFileSync('./data/Intel_SGX_Provisioning_Certification_RootCA.pem').toString();

        // Log the entire request body for debugging
        console.log('Request body:', req.body);

        // Extract necessary fields
        const { pubkey_list_hash, rsa_public_key, tee_report } = req.body.tee_return_data;

        // Pass the wrapped structure to verifyReport
        const attestor = new RemoteAttestor();
        const success = attestor.verifyReport(req.body, sgx_root_cert);
        console.log('Verification success:', success);
        console.log(attestor.exportLog());

        if (!success) {
            throw new Error('Verification failed');
        }

        // Compute the combined hash
        const { combinedHash,_ } = HashUtils.combineHashes(pubkey_list_hash, rsa_public_key, tee_report);

        // Add the combined hash to the response JSON
        res.status(200).json({ success, combinedHash });
    } catch (error) {
        console.error('Error during decryption:', error);
        res.status(500).send(`Decryption failed: ${(error as Error).message}`);
    }
    console.timeEnd('decrypt-key-shard');
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
