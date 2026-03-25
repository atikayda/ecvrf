// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import {ECVRFProver} from "../src/ECVRFProver.sol";
import {ECVRFVerifier} from "../src/ECVRFVerifier.sol";

contract Cli is Script {
    function run() external {
        string memory cmd = vm.envString("ECVRF_CMD");

        if (keccak256(bytes(cmd)) == keccak256("prove")) {
            ECVRFProver prover = new ECVRFProver();
            bytes32 sk = vm.envBytes32("ECVRF_SK");
            bytes memory alpha = vm.envBytes("ECVRF_ALPHA");
            (bytes memory pi, bytes32 beta) = prover.prove(sk, alpha);
            console.log(string.concat("ECVRF_OUT:", vm.toString(pi), ":", vm.toString(beta)));
        } else {
            ECVRFVerifier verifier = new ECVRFVerifier();
            bytes memory pk = vm.envBytes("ECVRF_PK");
            bytes memory pi = vm.envBytes("ECVRF_PI");
            bytes memory alpha = vm.envBytes("ECVRF_ALPHA");
            (bool valid, bytes32 beta) = verifier.verify(pk, pi, alpha);
            if (valid) {
                console.log(string.concat("ECVRF_OUT:true:", vm.toString(beta)));
            } else {
                console.log("ECVRF_OUT:false:null");
            }
        }
    }
}
