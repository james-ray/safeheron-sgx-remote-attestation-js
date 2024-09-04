import * as express from 'express';
import { Request, Response } from 'express';
import BN from 'bn.js';
import { RemoteAttestor } from './lib';
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

        res.send('Request logged successfully.');
    } catch (error) {
        console.error('Error during logging:', error);
        res.status(500).send(`Logging failed: ${(error as Error).message}`);
    }
    console.timeEnd('attestation');
});

app.post('/decrypt-key-shard', async (req: Request, res: Response) => {
    console.time('decrypt-key-shard');
    try {
        const sgx_root_cert = fs.readFileSync('./data/Intel_SGX_Provisioning_Certification_RootCA.pem').toString();

        // Log the entire request body for debugging
        console.log('Request body:', req.body);

        // Pass the wrapped structure to verifyReport
        const attestor = new RemoteAttestor();
        const success = attestor.verifyReport(req.body, sgx_root_cert);
        console.log('Verification success:', success);
        console.log(attestor.exportLog());

        if (!success) {
            throw new Error('Verification failed');
        }

        // const { tee_return_data, private_key } = req.body;
        // const { key_shard_pkg } = tee_return_data;
        //
        // // Decrypt each key shard
        // const decrypted_shards = key_shard_pkg.map((shard: any) => {
        //     const buffer = Buffer.from(shard.encrypt_key_info, 'hex');
        //     const decrypted = crypto.privateDecrypt(
        //         {
        //             key: private_key,
        //             padding: crypto.constants.RSA_PKCS1_PADDING,
        //         },
        //         buffer
        //     );
        //     return decrypted.toString('hex');
        // });

        res.status(200).json(success);
    } catch (error) {
        console.error('Error during decryption:', error);
        res.status(500).send(`Decryption failed: ${(error as Error).message}`);
    }
    console.timeEnd('decrypt-key-shard');
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
