// lib/index.ts

'use strict'
import * as BN from "bn.js"
import {ECIES} from '@safeheron/crypto-ecies'
import * as elliptic from "elliptic"
import * as crypto from "crypto"
import {UrlBase64} from "@safeheron/crypto-utils"
import * as cryptoJS from "crypto-js"
import {Certificate} from '@fidm/x509'
import {VerifyData} from "./interface";
import {Buffer} from "buffer";

const P256 = new elliptic.ec('p256')
// Define the key length and salt length
const key_bits_length = 1024;
const salt_length = crypto.constants.RSA_PSS_SALTLEN_AUTO;

enum SaltLength {
    AutoLength,
    EqualToHash
}

export class RemoteAttestor {
    private logInfo: string

    public constructor() {
        this.logInfo = ""
    }

    public encodeEMSA_PSS(message: string, keyBits: number, saltLength: SaltLength): string {
        const emBits = keyBits - 1;
        const emLen = Math.ceil(emBits / 8);

        if (emLen < 32 + 2) {
            throw new Error("emLen < 32 + 2");
        }

        let sLen;
        switch (saltLength) {
            case SaltLength.AutoLength:
                sLen = emLen - 2 - 32;
                break;
            case SaltLength.EqualToHash:
            default:
                sLen = 32;
                break;
        }

        const mHash = crypto.createHash('sha256').update(message).digest();

        if (emLen < 32 + sLen + 2) {
            throw new Error("emLen error: KeyBitLength is too short.");
        }

        const salt = sLen > 0 ? crypto.randomBytes(sLen) : Buffer.alloc(0);

        const padding1 = Buffer.alloc(8, 0x00);
        const mPrime = Buffer.concat([padding1, mHash, salt]);
        const H = crypto.createHash('sha256').update(mPrime).digest();

        const PS = Buffer.alloc(emLen - sLen - 32 - 2, 0x00);
        const DB = Buffer.concat([PS, Buffer.from([0x01]), salt]);

        const dbMask = crypto.createHash('sha256').update(H).digest();
        const maskedDB = Buffer.alloc(DB.length);
        for (let i = 0; i < DB.length; i++) {
            maskedDB[i] = DB[i] ^ dbMask[i];
        }

        const c = 255 >> (emLen * 8 - emBits);
        maskedDB[0] &= c;

        const em = Buffer.concat([maskedDB, H, Buffer.from([0xbc])]);
        return em.toString('hex');
    }

    public combineHashes(pubkey_list_hash: string, rsa_public_key: { e: string, n: string }, tee_report: string): {
        combined_hash: string,
        encoded_combined_hash: string
    } {
        const rsa_public_key_hash = this.sha256Digest(Buffer.concat([
            Buffer.from(rsa_public_key.e, 'hex'),
            Buffer.from(rsa_public_key.n, 'hex')
        ]), 'hex');

        let tee_report_bytes = UrlBase64.toBytes(tee_report);
        let tee_report_buffer = Buffer.from(tee_report_bytes);
        const qe_report_hash = this.getQeReportHash(tee_report_buffer);

        const combined_hash = this.sha256Digest(Buffer.concat([
            Buffer.from(pubkey_list_hash, 'hex'),
            Buffer.from(rsa_public_key_hash, 'hex'),
            Buffer.from(qe_report_hash, 'hex')
        ]), 'hex');

        const encoded_combined_hash = this.encodeEMSA_PSS(combined_hash, 1024, SaltLength.AutoLength);

        return { combined_hash: combined_hash, encoded_combined_hash: encoded_combined_hash };
    }

    public verifyReport(report: string | VerifyData, sgx_root_cert: string | Buffer): any {
        // Log the type and value of the report parameter

        this.logInfo = ""
        let input_data

        // Check if report is not null or undefined
        if (report == null) {
            throw new Error('Report is null or undefined');
        }

        if (typeof report === 'string') {
            input_data = JSON.parse(report);
        } else {
            input_data = report;
        }

        //console.log('input_data:', input_data);
        let json_data = input_data.tee_return_data;
        console.log('json_data:', json_data);
        const tee_report = json_data.tee_report;
        let tee_report_bytes = UrlBase64.toBytes(tee_report);
        let tee_report_buffer = Buffer.from(tee_report_bytes);

        const key_shard_pkg = json_data.key_shard_pkg;
        const json_pubkey_list_hash = json_data.pubkey_list_hash;
        // get User Data
        let private_key = input_data.private_key;
        const app_user_data = this.getAppReportHash(key_shard_pkg, json_pubkey_list_hash, private_key);
        const {success, key_info, app_hash, public_key} = app_user_data;
        if (!success) {
            throw new Error('App report hash generation failed');
        }

        // verify TEE Report
        const result = this.verifyReportStepByStep(tee_report_buffer, app_hash, Buffer.from(sgx_root_cert));
        if (result) {
            return {success: true, key_info, app_hash, public_key}
        }
    }

    public exportLog(): string {
        return this.logInfo
    }

    private appendLog(log: string) {
        this.logInfo += log + "\n"
    }

    // hash the message
    private sha256Digest(message, encoding) {
        return crypto.createHash('sha256')
            .update(message)
            .digest(encoding);
    }

    // get the key meta hash
    private getKeyMetaHash(json_key_info, key) {
        let hash = "";
        for (const [keyTemp, value] of Object.entries(json_key_info[key])) {
            hash += value;
        }
        let temp = hash.replace(/,/g, "");
        return this.sha256Digest(Buffer.from(temp), 'hex');
    }

    private genKeyPairDict(private_key_list: string) {
        let public_key_dict = {};
        const pri = new BN(private_key_list, 16)
        const pub = P256.g.mul(pri)
        public_key_dict[pub.encode("hex")] = private_key_list;

        return public_key_dict;
    }

    // get the public key list hash
    private sha256DigestArray(messages) {
        let sha256 = cryptoJS.algo.SHA256.create({asBytes: true});
        for (let m in messages) {
            sha256.update(messages[m]);
        }
        let digest = sha256.finalize();
        return digest.toString(cryptoJS.enc.Hex);
    }

    private getAppReportHash(key_shard_pkg, json_pubkey_list_hash, private_key): {
        success: boolean;
        key_info?: any;
        app_hash?: string;
        public_key?: any
    } {
        let hashList = [];
        let key_meta_hash;
        let plain_buffer;
        let index;
        let key_pair_dict = this.genKeyPairDict(private_key);
        // collect the public key
        for (let pkg_element in key_shard_pkg) {
            hashList.push(key_shard_pkg[pkg_element].public_key);
            if (key_shard_pkg[pkg_element].public_key in key_pair_dict) {
                index = pkg_element;
            }
        }

        if (index === undefined) {
            return {success: false};
        }

        // 1. decrypt the value of 'encrypt_key_info' using the corresponding private key
        // 2. parse the plain to a JSON object
        let encrypt_key_info = Buffer.from(key_shard_pkg[index].encrypt_key_info.toString(), 'hex');
        let pri_key = new BN(key_pair_dict[key_shard_pkg[index].public_key], 16);
        plain_buffer = Buffer.from(ECIES.decryptBytes(pri_key, encrypt_key_info));

        const key_info = JSON.parse(plain_buffer.toString());
        const public_key = key_shard_pkg[index].public_key
        this.appendLog("*************************************************************************************************************");
        this.appendLog("public_key: " + public_key);
        this.appendLog("*************************************************************************************************************");


        // Log each property of key_meta individually
        this.appendLog("key_meta.k: " + key_info.key_meta.k);
        this.appendLog("key_meta.l: " + key_info.key_meta.l);
        this.appendLog("key_meta.vkv: " + key_info.key_meta.vkv);
        this.appendLog("key_meta.vku: " + key_info.key_meta.vku);
        this.appendLog("key_meta.vkiArr: " + JSON.stringify(key_info.key_meta.vkiArr, null, 2));

        // Log each property of key_shard individually
        this.appendLog("key_shard.index: " + key_info.key_shard.index);
        this.appendLog("key_shard.private_key_shard: " + key_info.key_shard.private_key_shard);

        // get key meta hash
        key_meta_hash = this.getKeyMetaHash(key_info, 'key_meta');

        // verify the public key list hash
        let pubkey_list_hash = this.sha256DigestArray(hashList);
        this.appendLog("*************************************************************************************************************");
        this.appendLog("The public key list hash from data.json: " + pubkey_list_hash);
        this.appendLog("The calculated public key list hash: " + json_pubkey_list_hash);
        this.appendLog("*************************************************************************************************************");

        if (pubkey_list_hash != json_pubkey_list_hash) {
            return {success: false};
        }
        this.appendLog("1. The public key list hash has been verified successfully!\n");

        // hash the concatenation of public key list hash and key meta hash
        let app_hash = this.sha256Digest(Buffer.concat([Buffer.from(pubkey_list_hash, 'hex'), Buffer.from(key_meta_hash, 'hex')]), 'hex')
        return {success: true, key_info, app_hash, public_key}
    }

    private getQeReportHash(tee_report_buffer) {
        // the size and offset attestation public key
        let attest_public_key_offset = 0x1f4;
        let attest_public_key_size = 0x40;

        // the offset of authentication data structure
        let auth_data_struct_offset = 0x3f4;

        // the size and offset of authentication data
        let auth_data_len = tee_report_buffer.readUInt16LE(auth_data_struct_offset);
        let auth_data_offset = auth_data_struct_offset + 2;

        // get the attestation public key and authentication data
        let attest_public_key = tee_report_buffer.slice(attest_public_key_offset, attest_public_key_offset + attest_public_key_size);
        let auth_data = tee_report_buffer.slice(auth_data_offset, auth_data_offset + auth_data_len);

        // hash the concatenation of the attestation public key and authentication data
        return this.sha256Digest(Buffer.concat([attest_public_key, auth_data]), 'hex');
    }

    private verifyCertChain(tee_report_buffer, sgx_root_cert: Buffer) {
        // the offset of authentication data structure
        let auth_data_struct_offset = 0x3f4;

        // the size of authentication data
        let auth_data_size = tee_report_buffer.readUInt16LE(auth_data_struct_offset);

        // the offset of Certification Data
        let cert_chain_offset = 0x3f4 + 2 + auth_data_size + 2 + 4;
        // get certification chain
        let certification_data = tee_report_buffer.slice(cert_chain_offset);

        // get certification from certification chain
        let keyCert = [];
        const cert_length = 25;
        let k = 0;
        let u = 0;
        let tmp;
        for (let t = 0; t < 2; t++) {
            tmp = certification_data.slice(k, k + cert_length);
            keyCert.push(tmp);
            k += cert_length;
        }

        const pck_cert = Certificate.fromPEM(keyCert[0]);
        const processor_cert = Certificate.fromPEM(keyCert[1]);
        const sgx_root = Certificate.fromPEM(sgx_root_cert);

        // verify certification chain
        let result = processor_cert.checkSignature(pck_cert) == null &&
            pck_cert.checkSignature(sgx_root) == null;

        return [result, pck_cert];
    }

    // verify app report signature
    private verifyAppReportSig(tee_report_buffer) {
        // the offset and size of App Report Data
        let app_report_data_offset = 0x170;
        let app_report_data_size = 0x20;

        // get App Report Data from report
        let app_report_data = tee_report_buffer.slice(app_report_data_offset, app_report_data_offset + app_report_data_size);

        // hash the App Report Data
        let hash = this.sha256Digest(app_report_data, 'hex');

        // the offset and size of App Report Signature
        let app_signature_offset = 0x1f4;
        let app_signature_size = 0x40;

        // get App Report Signature from report
        let signature = tee_report_buffer.slice(app_signature_offset, app_signature_offset + app_signature_size);

        // verify the signature
        let sig = {
            r: signature.slice(0, 32).toString('hex'),
            s: signature.slice(32, 64).toString('hex')
        };

        // get the public key from the report
        let pub = P256.keyFromPublic(tee_report_buffer.slice(0x1f4, 0x1f4 + 0x40).toString('hex'), 'hex');

        // return the verification result
        return P256.verify(hash, sig, pub);
    }

    // verify qe report signature
    private verifyQeReportSig(tee_report_buffer, pck_cert) {
        // the offset and size of QE Report Data
        let qe_report_data_offset = 0x374;
        let qe_report_data_size = 0x20;

        // get QE Report Data from report
        let qe_report_data = tee_report_buffer.slice(qe_report_data_offset, qe_report_data_offset + qe_report_data_size);

        // hash the QE Report Data
        let hash = this.sha256Digest(qe_report_data, 'hex');

        // the offset and size of QE Report Signature
        let qe_signature_offset = 0x394;
        let qe_signature_size = 0x40;

        // get QE Report Signature from report
        let signature = tee_report_buffer.slice(qe_signature_offset, qe_signature_offset + qe_signature_size);
        let sig = {
            r: signature.slice(0, 32).toString('hex'),
            s: signature.slice(32, 64).toString('hex')
        };

        // get the public key from pckCert and convert it to a point on the elliptic curve
        let pub = P256.keyFromPublic(pck_cert.publicKey.keyRaw.toString('hex'), 'hex');

        // return the verification result
        return P256.verify(hash, sig, pub);
    };

    private verifyReportStepByStep(tee_report_buffer: Buffer, app_user_data, sgx_root_cert: Buffer) {

        const [cert_chain_result, pck_cert] = this.verifyCertChain(tee_report_buffer, sgx_root_cert);
        if (cert_chain_result !== true) {
            throw new Error('Cert chain verification failed');
        }
        this.appendLog("2. The cert chain has been verified successfully!\n");

        // verify App report signature
        const verify_app_result = this.verifyAppReportSig(tee_report_buffer);
        if (verify_app_result !== true) {
            throw new Error('App report signature verification failed');
        }
        this.appendLog("3. The App report signature has been verified successfully!\n");

        // verify QE report signature
        const verify_qe_result = this.verifyQeReportSig(tee_report_buffer, pck_cert);
        if (verify_qe_result !== true) {
            throw new Error('QE report signature verification failed');
        }
        this.appendLog("4. The QE report signature has been verified successfully!\n");

        const qe_report_hash = this.getQeReportHash(tee_report_buffer);

        // define the offset and size of App Report Data and QE Report Data
        let app_report_data_offset = 0x170;
        let app_report_data_size = 0x20;
        let qe_report_data_offset = 0x374;
        let qe_report_data_size = 0x20;

        // get Report Data from report
        let app_report_data = tee_report_buffer.slice(app_report_data_offset, app_report_data_offset + app_report_data_size).toString('hex');
        let qe_report_data = tee_report_buffer.slice(qe_report_data_offset, qe_report_data_offset + qe_report_data_size).toString('hex');

        // the data needed to be verified
        this.appendLog("*************************************************************************************************************");
        this.appendLog("The calculated user data: " + app_user_data);
        this.appendLog("The user data from tee_report: " + app_report_data);
        this.appendLog("*************************************************************************************************************");
        this.appendLog("The calculated QE report data: " + qe_report_hash);
        this.appendLog("The QE report data from tee_report: " + qe_report_data);
        this.appendLog("*************************************************************************************************************");

        // verify user data
        if (app_user_data !== app_report_data) {
            throw new Error('User data verification failed');
        }
        this.appendLog("5. User Data has been verified successfully!\n");

        if (qe_report_hash !== qe_report_data) {
            throw new Error('QE report data verification failed');
        }
        this.appendLog("6. QE Report Data has been verified successfully!\n");

        return true;
    }
}