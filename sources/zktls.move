#[allow(unused_field)]
module primus::zktls;

use std::string;
use sui::table::{Self, Table};

const EInvalidAddress: u64 = 0x1001;

// === Structs ===

/// @dev Structure representing an attestation, which is a signed statement of fact.
public struct Attestation has copy, drop, store {
    recipient: address, // The recipient of the attestation.
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

// @dev Structure representing an attestor, who is responsible for signing the attestation.
public struct Attestor has copy, drop, store {
    attestorAddr: address, // The address of the attestor.
    url: string::String, // URL associated with the attestor, such as a profile or additional information.
}

// === Events ===
/// Defines an event triggered when a new attestor is added
public struct AddAttestor has copy, drop {
    /// The address of the attestor.
    _address: address,
    /// Detailed information about the attestor (could be a struct or contract type).
    _attestor: Attestor,
}

/// Defines an event triggered when an existing attestor is removed
public struct DelAttestor has copy, drop {
    /// The address of the attestor.
    _address: address,
}

/// Represents the Primus ZKTLS
public struct PrimusZKTLS has key {
    id: UID, // Unique identifier for the Primus ZKTLS
    _attestorsMapping: Table<address, Attestor>, // Table to store attestors for each address
    _attestors: vector<Attestor>, // To store attestors
}

// === APIs ===

// Creates a new Primus ZKTLS
public fun createPrimusZktls(_owner: address, ctx: &mut TxContext) {
    let zktls = new(_owner, ctx);
    transfer::share_object(zktls)
}

fun new(_owner: address, ctx: &mut TxContext): PrimusZKTLS {
    let mut zktls = PrimusZKTLS {
        id: object::new(ctx),
        _attestorsMapping: table::new(ctx),
        _attestors: vector::empty(),
    };

    initialize(&mut zktls, _owner);

    zktls
}

/// @dev initialize function to set the owner of the contract.
/// This function is called during the contract deployment.
fun initialize(zktls: &mut PrimusZKTLS, _owner: address) {
    setupDefaultAttestor(zktls, _owner);
}

fun setupDefaultAttestor(zktls: &mut PrimusZKTLS, defaultAddr: address) {
    assert!(defaultAddr != @0x0, EInvalidAddress);

    let attestor = Attestor {
        attestorAddr: defaultAddr,
        url: string::utf8(b"https://primuslabs.xyz/"),
    };
    table::add(&mut zktls._attestorsMapping, defaultAddr, attestor);
    vector::push_back(&mut zktls._attestors, attestor)
}
