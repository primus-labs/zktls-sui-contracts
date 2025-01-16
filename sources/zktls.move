module primus::zktls;

use primus::utils;
use std::string::{Self, as_bytes, into_bytes};
use sui::bcs;
use sui::event;
use sui::hash::keccak256;
use sui::table::{Self, Table};

// === Errors ===

const EInvalidAddress: u64 = 0x1001;
const EOnlyOwner: u64 = 0x1002;
const ENotExistAttestor: u64 = 0x1003;
const EInvalidSignaturesLength: u64 = 0x1004;
const EInvalidSignatureLength: u64 = 0x1005;
const EInvalidSignature: u64 = 0x1006;

// === Structs ===

/// @dev Structure representing an attestation, which is a signed statement of fact.
public struct Attestation has copy, drop, store {
    recipient: vector<u8>, // The recipient address of the attestation.
    request: AttNetworkRequest, // The network request send to jsk and related to the attestation.
    reponseResolve: vector<AttNetworkResponseResolve>, // The response details responsed from jdk.
    data: string::String, // Real data in the pending body provided in JSON string format.
    attConditions: string::String, // Attestation parameters in JSON string format.
    timestamp: u64, // The timestamp of when the attestation was created.
    additionParams: string::String, // Extra data for more inormation.
    attestors: vector<Attestor>, // List of attestors who signed the attestation.
    signatures: vector<vector<u8>>, // signature from the attestor.
}

/// @dev Structure for representing a network request send to jsk and related to the attestation.
public struct AttNetworkRequest has copy, drop, store {
    url: string::String, // The URL to which the request is sent.
    header: string::String, // The request headers in JSON string format.
    method: string::String, // HTTP method used in the request (e.g., GET, POST).
    body: string::String, // The body of the request, typically in JSON format.
}

/// @dev Structure for resolving responses from a network request.
public struct AttNetworkResponseResolve has copy, drop, store {
    keyName: string::String, // The key in the response data to be resolved.
    parseType: string::String, // The format of the response data to parse (e.g., JSON, HTML).
    parsePath: string::String, // The path used to parse the response (e.g., JSONPath, XPath).
}

/// @dev Structure representing an attestor, who is responsible for signing the attestation.
public struct Attestor has copy, drop, store {
    attestorAddr: vector<u8>, // The address of the attestor.
    url: string::String, // URL associated with the attestor, such as a profile or additional information.
}

// === Events ===
/// Defines an event triggered when a new attestor is added
public struct AddAttestor has copy, drop {
    /// The address of the attestor.
    _address: vector<u8>,
    /// Detailed information about the attestor (could be a struct or contract type).
    _attestor: Attestor,
}

/// Defines an event triggered when an existing attestor is removed
public struct DelAttestor has copy, drop {
    /// The address of the attestor.
    _address: vector<u8>,
}

/// Represents the Primus ZKTLS
public struct PrimusZKTLS has key {
    id: UID, // Unique identifier for the Primus ZKTLS
    owner: address, // Address of the Primus ZKTLS owner
    _attestorsMapping: Table<vector<u8>, Attestor>, // Table to store attestors for each address
    _attestors: vector<Attestor>, // To store attestors
}

// === Helper Functions ===

/// Creates a new attestor
public fun createAttestor(attestorAddr: vector<u8>, url: string::String): Attestor {
    Attestor {
        attestorAddr,
        url,
    }
}

public fun createAttNetworkRequest(
    url: string::String,
    header: string::String,
    method: string::String,
    body: string::String,
): AttNetworkRequest {
    AttNetworkRequest {
        url,
        header,
        method,
        body,
    }
}

public fun createAttNetworkResponseResolve(
    keyName: string::String,
    parseType: string::String,
    parsePath: string::String,
): AttNetworkResponseResolve {
    AttNetworkResponseResolve {
        keyName,
        parseType,
        parsePath,
    }
}

public fun createAttestation(
    recipient: vector<u8>,
    request: AttNetworkRequest,
    reponseResolve: vector<AttNetworkResponseResolve>,
    data: string::String,
    attConditions: string::String,
    timestamp: u64,
    additionParams: string::String,
    attestors: vector<Attestor>,
    signatures: vector<vector<u8>>,
): Attestation {
    Attestation {
        recipient,
        request,
        reponseResolve,
        data,
        attConditions,
        timestamp,
        additionParams,
        attestors,
        signatures,
    }
}

// === Public Functions ===

/// Creates a new Primus ZKTLS
public fun createPrimusZktls(_owner: address, defaultAttestor: vector<u8>, ctx: &mut TxContext) {
    let zktls = new(_owner, defaultAttestor, ctx);
    transfer::share_object(zktls)
}

fun new(_owner: address, defaultAttestor: vector<u8>, ctx: &mut TxContext): PrimusZKTLS {
    let mut zktls = PrimusZKTLS {
        id: object::new(ctx),
        owner: _owner,
        _attestorsMapping: table::new(ctx),
        _attestors: vector::empty(),
    };

    initialize(&mut zktls, defaultAttestor);

    zktls
}

/// @dev initialize function to set the owner of the contract.
/// This function is called during the contract deployment.
fun initialize(zktls: &mut PrimusZKTLS, defaultAttestor: vector<u8>) {
    setupDefaultAttestor(zktls, defaultAttestor);
}

fun setupDefaultAttestor(zktls: &mut PrimusZKTLS, defaultAttestor: vector<u8>) {
    assert!(defaultAttestor != vector[], EInvalidAddress);

    let attestor = Attestor {
        attestorAddr: defaultAttestor,
        url: string::utf8(b"https://primuslabs.xyz/"),
    };
    table::add(&mut zktls._attestorsMapping, defaultAttestor, attestor);
    vector::push_back(&mut zktls._attestors, attestor)
}

/// @dev Allows the owner to set the attestor for a specific recipient.
///
/// Requirements:
/// - The caller must be the owner of the contract.
///
/// @param attestor The attestor to associate with the recipient.
public fun setAttestor(zktls: &mut PrimusZKTLS, attestor: Attestor, ctx: &mut TxContext) {
    assert!(zktls.owner == tx_context::sender(ctx), EOnlyOwner);
    assert!(attestor.attestorAddr != vector[], EInvalidAddress);

    // Set the attestor for the recipient, update if exist
    if (table::contains(&zktls._attestorsMapping, attestor.attestorAddr)) {
        *table::borrow_mut(&mut zktls._attestorsMapping, attestor.attestorAddr) = attestor;
        let mut i = 0;
        while (i < vector::length(&zktls._attestors)) {
            let v = vector::borrow_mut(&mut zktls._attestors, i);
            if (v.attestorAddr == attestor.attestorAddr) {
                *v = attestor;
                break
            };
            i = i + 1
        };
    } else {
        table::add(&mut zktls._attestorsMapping, attestor.attestorAddr, attestor);
        vector::push_back(&mut zktls._attestors, attestor)
    };

    event::emit(AddAttestor { _address: attestor.attestorAddr, _attestor: attestor });
}

/// @dev Removes the attestor for a specific recipient.
///
/// Requirements:
/// - The caller must be the owner of the contract.
/// @param attestorAddr The address of the recipient whose attestor is to be removed.
public fun removeAttestor(zktls: &mut PrimusZKTLS, attestorAddr: vector<u8>, ctx: &mut TxContext) {
    assert!(zktls.owner == tx_context::sender(ctx), EOnlyOwner);
    assert!(attestorAddr != vector[], EInvalidAddress);
    assert!(table::contains(&zktls._attestorsMapping, attestorAddr), ENotExistAttestor);

    table::remove(&mut zktls._attestorsMapping, attestorAddr);

    // update _attestors
    let mut i = 0;
    let length = vector::length(&zktls._attestors);
    while (i < length) {
        let v = vector::borrow(&zktls._attestors, i);
        if (v.attestorAddr == attestorAddr) {
            vector::swap(&mut zktls._attestors, i, length-1);
            vector::pop_back(&mut zktls._attestors);
            break
        };
        i = i + 1
    };

    event::emit(DelAttestor { _address: attestorAddr });
}

/// @dev Verifies the validity of a given attestation.
///
/// Requirements:
/// - Attestation must contain valid signatures from attestors.
/// - The data, request, and response must be consistent.
/// - The attestation must not be expired based on its timestamp.
///
/// @param attestation The attestation data to be verified.
public fun verifyAttestation(zktls: &PrimusZKTLS, attestation: Attestation) {
    assert!(vector::length(&attestation.signatures)==1, EInvalidSignaturesLength);

    let signature = attestation.signatures[0];
    assert!(vector::length(&signature)==65, EInvalidSignatureLength);

    let msg = encodeAttestationWithoutHash(attestation);
    let attestorAddr = utils::ecrecover_to_eth_address(signature, msg);

    let mut i = 0;
    let length = vector::length(&zktls._attestors);
    while (i < length) {
        let v = vector::borrow(&zktls._attestors, i);
        if (v.attestorAddr == attestorAddr) {
            break
        };
        i = i + 1
    };

    assert!(i < length, EInvalidSignature);
}

/// @dev Encodes an attestation into a bytes32 hash.
///
/// The encoding includes all fields in the attestation structure,
/// ensuring a unique hash representing the data.
///
/// @param attestation The attestation data to encode.
/// @return A bytes32 hash of the encoded attestation.
public fun encodeAttestation(attestation: Attestation): vector<u8> {
    keccak256(&encodeAttestationWithoutHash(attestation))
}

public fun encodeAttestationWithoutHash(attestation: Attestation): vector<u8> {
    let mut timestamp = bcs::to_bytes(&attestation.timestamp);
    timestamp.reverse();

    let mut encode_data = vector::empty<u8>();

    vector::append(&mut encode_data, attestation.recipient);
    vector::append(&mut encode_data, encodeRequest(attestation.request));
    vector::append(&mut encode_data, encodeResponse(attestation.reponseResolve));
    vector::append(&mut encode_data, into_bytes(attestation.data));
    vector::append(&mut encode_data, into_bytes(attestation.attConditions));
    vector::append(&mut encode_data, timestamp);
    vector::append(&mut encode_data, into_bytes(attestation.additionParams));

    encode_data
}

/// @dev Encodes a network request into a bytes32 hash.
///
/// The encoding includes the URL, headers, HTTP method, and body of the request.
///
/// @param request The network request to encode.
/// @return A bytes32 hash of the encoded network request.
public fun encodeRequest(request: AttNetworkRequest): vector<u8> {
    let mut encodeData = b"".to_string();
    encodeData.append(request.url);
    encodeData.append(request.header);
    encodeData.append(request.method);
    encodeData.append(request.body);

    keccak256(as_bytes(&encodeData))
}

/// @dev Encodes a list of network response resolutions into a bytes32 hash.
///
/// This iterates through the response array and encodes each field, creating
/// a unique hash representing the full response data.
///
/// @param responses The array of response resolutions to encode.
/// @return A bytes32 hash of the encoded response resolutions.
public fun encodeResponse(responses: vector<AttNetworkResponseResolve>): vector<u8> {
    let mut encodeData = b"".to_string();
    let mut i = 0;
    let length = vector::length(&responses);
    while (i < length) {
        let response = vector::borrow(&responses, i);
        encodeData.append(response.keyName);
        encodeData.append(response.parseType);
        encodeData.append(response.parsePath);
        i = i + 1
    };

    keccak256(as_bytes(&encodeData))
}
