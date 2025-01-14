#[allow(unused_use)]

#[test_only]
module primus::primus_tests;

use primus::zktls;
use sui::test_scenario;

#[test, expected_failure(abort_code = zktls::EInvalidAddress)]
fun test_create_primus_zktls_fail() {
    let owner = @0x0;
    let user1 = @0xA1;

    let mut scenario_val = test_scenario::begin(user1);
    let scenario = &mut scenario_val;

    test_scenario::next_tx(scenario, owner);
    {
        zktls::createPrimusZktls(owner, test_scenario::ctx(scenario));
    };

    test_scenario::end(scenario_val);
}

#[test]
fun test_zktls() {
    let owner = @0xC0FFEE;
    let user1 = @0xA1;

    let mut scenario_val = test_scenario::begin(user1);
    let scenario = &mut scenario_val;

    test_scenario::next_tx(scenario, owner);
    {
        zktls::createPrimusZktls(owner, test_scenario::ctx(scenario));
    };

    test_scenario::end(scenario_val);
}
