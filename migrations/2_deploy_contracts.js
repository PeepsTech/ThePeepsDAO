var PeepsFactory = artifacts.require('../contracts/PeepsFactory.sol');

var PeepsFactory = artifacts.require("PeepsFactory");

module.exports = function(deployer) {
    deployer.deploy(PeepsFactory)
};
