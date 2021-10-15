fn main() {

    println!("Hello, world!");
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use bdk::blockchain::noop_progress;
    use bdk::database::MemoryDatabase;
    use bdk::electrum_client::Client;
    use bdk::{KeychainKind, Wallet};
    use bdk::bitcoin::{Network, PrivateKey, PublicKey};
    use bdk::bitcoin::hashes::hex::ToHex;
    use bdk::bitcoin::util::bip32::ExtendedPrivKey;
    use bdk::blockchain::ElectrumBlockchain;
    use bdk::wallet::AddressIndex;
    use bdk::bitcoin::secp256k1::Secp256k1;
    use bitcoin::hashes::hex::FromHex;

    #[tokio::test]
    async fn simple_container() {
        let client = Client::new("ssl://electrum.blockstream.info:50002").unwrap();
        let ext_priv_key_seed = b"this is a long complicated 64 bytes private ke";
        let ext_priv_key = ExtendedPrivKey::new_master(Network::Testnet, ext_priv_key_seed).unwrap();
        let wallet = bdk::Wallet::new(
            bdk::template::Bip84(ext_priv_key, KeychainKind::External),
            Some(bdk::template::Bip84(ext_priv_key, KeychainKind::Internal)),
            ext_priv_key.network,
            MemoryDatabase::default(),
            ElectrumBlockchain::from(client),
        ).unwrap();

        wallet.sync(noop_progress(), None).unwrap();

        let address = wallet.get_address(AddressIndex::New).unwrap().address;
        dbg!(&address.address_type());
        dbg!(&address.script_pubkey());



        println!("Descriptor balance: {} SAT", wallet.get_balance().unwrap());
    }

    #[test]
    fn pk_pkh() {
        let seed = b"this is a long 32 bytes private ";
        let sk = PrivateKey::from_slice(seed, Network::Testnet).unwrap();
        let pk = PublicKey::from_private_key(&Secp256k1::new(), &sk);
        assert_eq!(pk.pubkey_hash().to_hex(), "58075fb04ec5c2822378da36520b925e062abf01");

        let address = bdk::bitcoin::Address::p2wpkh(&pk, Network::Testnet).unwrap();
        dbg!(&address.script_pubkey());
        dbg!(address);
        // pukey hash op_dup op_equal op_checksigverify

        let raw_spend_tx = "0200000000010175057815cf17c606873c439cc898e4a6fce70947aec42fb7649c4a816d0c4a310000000000feffffff02a08601000000000016001458075fb04ec5c2822378da36520b925e062abf0189b5cd000000000016001424dc328297ed3882ed058da646766d9b56dd1e4f02473044022034dd715366017f66156f0d393977cb0870de46278f26e6e45e2cd328c036ded3022072c9fe8e0bdb53c8c86b79a08e2dda36d51d8d4d8a5a7ba963f374bc8df35cb10121036e53094f8763aa0caf3fad9001548d764ced4dde922a4e4851672d30a30204c4d8072000";
        let tx: bdk::bitcoin::Transaction = bitcoin::consensus::deserialize(&Vec::from_hex(raw_spend_tx).unwrap()).unwrap();

        dbg!(&tx);


    }
}