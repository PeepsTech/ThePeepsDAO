
//Mirror of Factory in Full PeepsDAO.sol

pragma solidity ^0.6.0;

import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/math/SafeMath.sol";
import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/utils/ReentrancyGuard.sol";
import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/ownership/Ownable.sol";
import "/PeepsMoloch.sol";

contract PeepsMolochFactory is ReentrancyGuard {
    using SafeMath for uint256;

    //constants and mappings
    PeepsMoloch[] public peepsmolochs;

    //events
    event NewPeepsMoloch(address indexed _summoner, address indexed newPeeps);

   // deploy a new contract
   function createPeepsMoloch(
     address _summoner,
     address _peepsWallet, //set wallet address on front-end
     address[] memory _approvedTokens,
     uint256 _periodDuration,
     uint256 _votingPeriodLength,
     uint256 _gracePeriodLength,
     uint256 _emergencyExitWait,
     uint256 _proposalDeposit,
     uint256 _dilutionBound,
     uint256 _processingReward,
     uint256 _minDonation,
     uint256 _adminFee, //denominator for the admin fee, default to 32 which gets to 3.125%
     bool _canQuit
       )
    public returns (address _newPeeps) {
     PeepsMoloch newPeeps = new PeepsMoloch(
      _summoner,
      _peepsWallet,
      _approvedTokens,
      _periodDuration,
      _votingPeriodLength,
      _gracePeriodLength,
      _emergencyExitWait,
      _proposalDeposit,
      _dilutionBound,
      _processingReward,
      _minDonation,
      _adminFee,
      _canQuit);

    emit NewPeepsMoloch(_summoner, address(_newPeeps));
    return address(newPeeps);
  }

    function getPeepsMolochCount() public view returns (uint256 PeepsMolochCount) {
        return peepsmolochs.length;
    }
}
