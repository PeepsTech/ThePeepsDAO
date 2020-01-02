var PeepsMoloch = artifacts.require('../contracts/PeepsMoloch.sol');

//standard testing params (probably not good for production)
const summoner = ""; //choose your summoner
const depositToken = ['']; //set an ERC20 Token
const periodDuration = 60; //seconds
const votingPeriodLength = 3;  //60 x 3 = 180 seconds
const gracePeriodLength = 3;
const emergencyExitWait = 2;
const proposalDeposit = 2;
const dilutionBound = 3;
const processingReward = 2;
const minDonation = 5; //min tribute required to join <-- this calculates shares issued 
const canQuit = false; //determines whether member needs admin permission to rage quit

var GuildBank = artifacts.require("GuildBank");
var PeepsMoloch = artifacts.require("PeepsMoloch");

module.exports = function(deployer) {
    deployer.deploy(GuildBank, depositToken)
    deployer.deploy(PeepsMoloch, summoner, depositToken, periodDuration,
    	votingPeriodLength, gracePeriodLength, proposalDeposit, processingReward, emergencyExitWait, proposalDeposit, minDonation, canQuit);
};
