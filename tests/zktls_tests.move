#[test_only]
module primus::primus_tests;

use primus::zktls;
use sui::event;
use sui::test_scenario;

#[test, expected_failure(abort_code = zktls::EInvalidAddress)]
fun test_create_primus_zktls_fail() {
    let owner = @0xC0FFEE;
    let defaultAttestor = vector[];
    let user1 = @0xA1;

    let mut scenario_val = test_scenario::begin(user1);
    let scenario = &mut scenario_val;

    test_scenario::next_tx(scenario, owner);
    {
        zktls::createPrimusZktls(owner, defaultAttestor, test_scenario::ctx(scenario));
    };

    test_scenario::end(scenario_val);
}

#[test, expected_failure(abort_code = zktls::EOnlyOwner)]
fun test_zktls_creat_attestor_fail() {
    let owner = @0xC0FFEE;
    let defaultAttestor = x"AfC79DFa002408C479dDa0384831E73616B721C4";
    let attestor1 = x"a302153842e73FCEeEcFdA568de2A4A97C000BFb";
    let user1 = @0xA1;

    let mut scenario_val = test_scenario::begin(user1);
    let scenario = &mut scenario_val;

    test_scenario::next_tx(scenario, owner);
    {
        zktls::createPrimusZktls(owner, defaultAttestor, test_scenario::ctx(scenario));
    };

    test_scenario::next_tx(scenario, user1);
    {
        let attestor = zktls::createAttestor(attestor1, b"https://@0xF1.com/".to_string());
        let mut _zktls = test_scenario::take_shared<zktls::PrimusZKTLS>(scenario);

        zktls::setAttestor(&mut _zktls, attestor, test_scenario::ctx(scenario));

        test_scenario::return_shared(_zktls);
    };

    test_scenario::end(scenario_val);
}

fun create_simple_request(): zktls::AttNetworkRequest {
    let request = zktls::createAttNetworkRequest(
        b"url".to_string(),
        b"header".to_string(),
        b"method".to_string(),
        b"body".to_string(),
    );
    request
}

fun create_simple_responses(): vector<zktls::AttNetworkResponseResolve> {
    let response = zktls::createAttNetworkResponseResolve(
        b"keyName".to_string(),
        b"parseType".to_string(),
        b"parsePath".to_string(),
    );
    vector[response, response]
}

fun create_simple_attestation(
    request: zktls::AttNetworkRequest,
    responses: vector<zktls::AttNetworkResponseResolve>,
    signatures: vector<vector<u8>>,
): zktls::Attestation {
    let attestation = zktls::createAttestation(
        x"a302153842e73FCEeEcFdA568de2A4A97C000BFb",
        request,
        responses,
        b"data".to_string(),
        b"attConditions".to_string(),
        0x1234567890abcdef,
        b"additionParams".to_string(),
        vector[],
        signatures,
    );
    attestation
}

#[test]
fun test_zktls_encode_request() {
    let request = create_simple_request();

    let hash = zktls::encodeRequest(request);
    assert!(hash == x"6516ff20b12fab566bffa0007a21e4790d74345696806422615c31a2bbe04698", 0);
}

#[test]
fun test_zktls_encode_response() {
    let responses = create_simple_responses();

    let hash = zktls::encodeResponse(responses);
    assert!(hash == x"7bf1beb260e2560e9c8dc1c7d859b5fa15fab01041779bdd85ed5096125a9441", 0);
}

#[test]
fun test_zktls_encode_attestation() {
    let request = create_simple_request();
    let responses = create_simple_responses();
    let attestation = create_simple_attestation(request, responses, vector[x"00"]);

    let hash = zktls::encodeAttestation(attestation);
    assert!(hash == x"3fb07c6d8d8c2870cd1b57fe65cf97426760716f965b4769ef5d7eec90d3489d", 0);
}

#[test]
fun test_zktls() {
    let owner = @0xC0FFEE;
    let defaultAttestor = x"AfC79DFa002408C479dDa0384831E73616B721C4";
    let user1 = @0xA1;

    let mut scenario_val = test_scenario::begin(user1);
    let scenario = &mut scenario_val;

    // createPrimusZktls
    test_scenario::next_tx(scenario, owner);
    {
        zktls::createPrimusZktls(owner, defaultAttestor, test_scenario::ctx(scenario));
    };

    // setAttestor
    test_scenario::next_tx(scenario, owner);
    {
        let mut _zktls = test_scenario::take_shared<zktls::PrimusZKTLS>(scenario);
        {
            let attestor1 = x"e05fcC23807536bEe418f142D19fa0d21BB0cfF7";
            let attestor = zktls::createAttestor(attestor1, b"https://@0xF1.com/".to_string());
            zktls::setAttestor(&mut _zktls, attestor, test_scenario::ctx(scenario));
            let events = event::events_by_type<zktls::AddAttestor>();
            assert!(vector::length(&events) == 1, 0);
        };
        {
            let attestor2 = x"570B4A56255f7509266783a81C3438fd5D7067B6";
            let attestor = zktls::createAttestor(attestor2, b"https://@0xF2.com/".to_string());
            zktls::setAttestor(&mut _zktls, attestor, test_scenario::ctx(scenario));
            let events = event::events_by_type<zktls::AddAttestor>();
            assert!(vector::length(&events) == 2, 0);
        };
        test_scenario::return_shared(_zktls);
    };

    // removeAttestor
    test_scenario::next_tx(scenario, owner);
    {
        let mut _zktls = test_scenario::take_shared<zktls::PrimusZKTLS>(scenario);
        {
            let attestor2 = x"570B4A56255f7509266783a81C3438fd5D7067B6";
            zktls::removeAttestor(&mut _zktls, attestor2, test_scenario::ctx(scenario));
            let events = event::events_by_type<zktls::DelAttestor>();
            assert!(vector::length(&events) == 1, 0);
        };
        test_scenario::return_shared(_zktls);
    };

    // verifyAttestation
    test_scenario::next_tx(scenario, user1);
    {
        let mut signatures = vector<vector<u8>>[];
        let signature =
            x"8df749a149333d8a8ed2da1e943c13fdf857150d9816a675b2d542e2904d263d6beddfe207e39bd7ceca35f5d3f13bebef094861ad538e8288d53cd7234267281b";
        signatures.push_back(signature);

        let request = create_simple_request();
        let responses = create_simple_responses();
        let attestation = create_simple_attestation(request, responses, vector[signature]);

        let mut _zktls = test_scenario::take_shared<zktls::PrimusZKTLS>(scenario);
        zktls::verifyAttestation(&_zktls, attestation);
        test_scenario::return_shared(_zktls);
    };
    test_scenario::end(scenario_val);
}
