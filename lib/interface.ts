export interface VerifyData{
    tee_return_data: {
        pubkey_list_hash: string;
        key_shard_pkg: KeyShardPKGItem[];
        tee_report: string;
        rsa_public_key: {
            e: string;
            n: string;
        };
        server_pubkey: string;
    },
    private_key: string
}

interface KeyShardPKGItem{
    public_key: string;
    encrypt_key_info: string
}
