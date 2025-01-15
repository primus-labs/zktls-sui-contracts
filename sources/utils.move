module primus::utils;

use sui::ecdsa_k1;

/// Convert u64 to bytes in big endian
public fun u64_to_bytes(value: u64): vector<u8> {
    let mut bytes = vector::empty<u8>();
    vector::push_back(&mut bytes, ((value >> 56) & 0xFF) as u8);
    vector::push_back(&mut bytes, ((value >> 48) & 0xFF) as u8);
    vector::push_back(&mut bytes, ((value >> 40) & 0xFF) as u8);
    vector::push_back(&mut bytes, ((value >> 32) & 0xFF) as u8);
    vector::push_back(&mut bytes, ((value >> 24) & 0xFF) as u8);
    vector::push_back(&mut bytes, ((value >> 16) & 0xFF) as u8);
    vector::push_back(&mut bytes, ((value >> 8) & 0xFF) as u8);
    vector::push_back(&mut bytes, (value & 0xFF) as u8);
    bytes
}

/// Ref: https://github.com/MystenLabs/sui/blob/main/examples/move/crypto/ecdsa_k1/sources/example.move
/// Recover the Ethereum address using the signature and message, assuming
/// the signature was produced over the Keccak256 hash of the message.
/// Output an object with the recovered address to recipient.
public entry fun ecrecover_to_eth_address(mut signature: vector<u8>, msg: vector<u8>): vector<u8> {
    // Normalize the last byte of the signature to be 0 or 1.
    let v = vector::borrow_mut(&mut signature, 64);
    if (*v == 27) {
        *v = 0;
    } else if (*v == 28) {
        *v = 1;
    } else if (*v > 35) {
        *v = (*v - 1) % 2;
    };

    // Ethereum signature is produced with Keccak256 hash of the message, so the last param is 0.
    let pubkey = ecdsa_k1::secp256k1_ecrecover(&signature, &msg, 0);
    let uncompressed = ecdsa_k1::decompress_pubkey(&pubkey);

    // Take the last 64 bytes of the uncompressed pubkey.
    let mut uncompressed_64 = vector::empty<u8>();
    let mut i = 1;
    while (i < 65) {
        let value = vector::borrow(&uncompressed, i);
        vector::push_back(&mut uncompressed_64, *value);
        i = i + 1;
    };

    // Take the last 20 bytes of the hash of the 64-bytes uncompressed pubkey.
    let hashed = sui::hash::keccak256(&uncompressed_64);
    let mut addr = vector::empty<u8>();
    let mut i = 12;
    while (i < 32) {
        let value = vector::borrow(&hashed, i);
        vector::push_back(&mut addr, *value);
        i = i + 1;
    };

    addr

    // Transfer an output data object holding the address to the recipient.
    // transfer::public_transfer(addr_object, recipient)
}
