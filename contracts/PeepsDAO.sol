pragma solidity ^0.6.1;

import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/math/SafeMath.sol";
import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/token/ERC20/IERC20.sol";
import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/ownership/Ownable.sol";
import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/access/Roles.sol";
import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/utils/ReentrancyGuard.sol";

contract PeepsMolochFactory is ReentrancyGuard {
    using SafeMath for uint256;

    //constants and mappings
    PeepsMoloch private P;
    address[] public PeepsMolochs;


    //events
    event NewPeepsMoloch(address indexed _summoner, address indexed P, address indexed _peepsWallet, uint _minDonation, bool _canQuit);


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
    public {
     P = new PeepsMoloch(
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

    PeepsMolochs.push(address(P));
    emit NewPeepsMoloch(_summoner, address(P), _peepsWallet, _minDonation, _canQuit);
  }

    function getPeepsMolochCount() public view returns (uint256 PeepsMolochCount) {
        return PeepsMolochs.length;
    }
}


// *******************
// PeepsMoloch Contract
// *******************

contract PeepsMoloch is Context, ReentrancyGuard {
    using SafeMath for uint256;
    using Roles for Roles.Role;

    // ****************
    // GLOBAL CONSTANTS
    // ****************
    uint256 public periodDuration; // default = 3600 = 1 hours in seconds
    uint256 public votingPeriodLength; // default = 168 periods (7 days)
    uint256 public gracePeriodLength; // default = 72 periods (3 days)
    uint256 public emergencyExitWait; // default = 168 periods (7 days) - if proposal has not been processed after this time, its logic will be skipped
    uint256 public proposalDeposit; // default = 0.01 ETH (~$1.25 worth of ETH at deployment)
    uint256 public dilutionBound; // default = 3 - maximum multiplier a YES voter will be obligated to pay in case of mass ragequit
    uint256 public processingReward; // default = 0.01 ETH - amount to give to whomever processes a proposal
    uint256 public summoningTime; // needed to determine the current period
    uint256 public minDonation; // min donation to join
    uint256 public adminFee; // admin fee demoninator, so default is 32 to get to a 3.125% fee when divided into 100
    bool public canQuit;

    address public depositToken; // reference to the deposit token
    address public peepsWallet; // reference to wallet for collecting fees

    // HARD-CODED LIMITS
    // These numbers are quite arbitrary; they are small enough to avoid overflows when doing calculations
    // with periods or shares, yet big enough to not limit reasonable use cases.
    uint256 constant MAX_VOTING_PERIOD_LENGTH = 10**18; // maximum length of voting period
    uint256 constant MAX_GRACE_PERIOD_LENGTH = 10**18; // maximum length of grace period
    uint256 constant MAX_DILUTION_BOUND = 10**18; // maximum dilution bound
    uint256 constant MAX_NUMBER_OF_SHARES = 10**18; // maximum number of shares that can be minted
    uint256 constant MAX_TOKEN_WHITELIST_COUNT = 50; // maximum number of whitelisted tokens
    uint256 constant MAX_TOKEN_GUILDBANK_COUNT = 25; // maximum number of tokens with non-zero balance in guildbank

    // ***************
    // EVENTS
    // ***************
    event SummonComplete(address indexed summoner, address[] tokens, uint256 summoningTime, uint256 periodDuration, uint256 votingPeriodLength, uint256 gracePeriodLength, uint256 proposalDeposit, uint256 processingReward);
    event SubmitProposal(address indexed applicant, uint256 sharesRequested, uint256 tributeOffered, address tributeToken, uint256 paymentRequested, address paymentToken, string details, bool[5] flags, uint256 proposalId, address indexed memberAddress);
    event SubmitVote(uint256 indexed proposalIndex, address indexed delegateKey, address indexed memberAddress, uint8 uintVote);
    event Ragequit(address indexed memberAddress, uint256 sharesToBurn);
    event CancelProposal(uint256 indexed proposalIndex, address applicantAddress);
    event UpdateDelegateKey(address indexed memberAddress, address newDelegateKey);
    event ProcessProposal(uint256 indexed proposalIndex, uint256 indexed proposalId, bool didPass);
    event ProcessGuildKickProposal(uint256 indexed proposalIndex, uint256 indexed proposalId, bool didPass);
    event SponsorProposal(address indexed delegateKey, address indexed memberAddress, uint256 proposalIndex, uint256 proposalQueueIndex, uint256 startingPeriod);
    event MemberAdded(address indexed _newMemberAddress, uint256 _tributeAmount, uint256 _shares);
    event AdminAdded(address indexed account);
    event AdminRemoved(address indexed account);
    event CanQuit(address indexed member);
    event TokenAdded (address indexed _tokenToWhitelist);
    event Withdraw(address indexed memberAddress, address token, uint256 amount);
    event feeWithdraw(address indexed peepsWallet, address token, uint256 amount);

    // *******************
    // INTERNAL ACCOUNTING
    // *******************
    uint256 public proposalCount = 0; // total proposals submitted
    uint256 public totalShares = 0; // total shares across all members
    uint256 public totalDepositTokens = 0; // total number of deposit tokens in guild bank
    uint256 public totalGuildBankTokens = 0; // total tokens with non-zero balance in guild bank

    address public constant GUILD = address(0xdead);
    address public constant ESCROW = address(0xbeef);
    address public constant TOTAL = address(0xbabe);

    mapping (address => mapping(address => uint256)) public userTokenBalances; // userTokenBalances[userAddress][tokenAddress]

    enum Vote {
        Null, // default value, counted as abstention
        Yes,
        No
    }

    struct Member {
        address delegateKey; // the key responsible for submitting proposals and voting - defaults to member address unless updated
        uint256 shares; // the # of shares assigned to this member
        uint256 highestIndexYesVote; // highest proposal index # on which the member voted YES
        uint256 jailed; // set to proposalIndex of a passing guild kick proposal for this member, prevents voting on and sponsoring proposals
        bool exists; // always true once a member has been created
        bool canQuit; //determines whether member can rage quit without admin approval
    }

    struct Proposal {
        address applicant; // used for identifying the member in a guildkick proposal
        address proposer; // whoever submitted the proposal (can be non-member)
        address sponsor; // the member who sponsored the proposal
        uint256 sharesRequested; // the # of shares the applicant is requesting
        uint256 tributeOffered; // amount of tokens offered as tribute
        address tributeToken; // tribute token contract reference
        uint256 paymentRequested; // the payments requested for each applicant
        address paymentToken; // token to send payment in
        uint256 startingPeriod; // the period in which voting can start for this proposal
        uint256 yesVotes; // the total number of YES votes for this proposal
        uint256 noVotes; // the total number of NO votes for this proposal
        bool[5] flags; // [sponsored, processed, didPass, cancelled, guildkick]
        // 0. sponsored - true only if the proposal has been submitted by a member
        // 1. processed - true only if the proposal has been processed
        // 2. didPass - true only if the proposal passed
        // 3. cancelled - true only if the proposer called cancelProposal before a member sponsored the proposal
        // 4. guildkick - true only if this is a guild kick proposal, NOTE - applicant is target of guild kick
        string details; // proposal details - could be IPFS hash, plaintext, or JSON
        uint256 maxTotalSharesAtYesVote; // the maximum # of total shares encountered at a yes vote on this proposal
        mapping (address => Vote) votesByMember; // the votes on this proposal by each member
    }

    mapping (address => bool) public tokenWhitelist;
    address[] public approvedTokens; //deployed version will set to be only ETH or DAI.

    mapping (address => bool) public proposedToKick; // true if a member has been proposed to be kicked (to avoid duplicate guild kick proposals)

    //mapping of members by address
    mapping(address => Member) public members;
    //mapping of delegates by members
    mapping(address => address) public memberAddressByDelegateKey;

    //proposal mapping
    mapping(uint256 => Proposal) public proposals;
    //proposal queue for tracking number and order of proposals
    uint256[] public proposalQueue;


    // *********
    // MODIFIERS
    // *********

    Roles.Role private _admins;

    modifier onlyMember {
        require(members[msg.sender].shares > 0, "not a member");
        _;
    }

    modifier onlyDelegate {
        require(members[memberAddressByDelegateKey[msg.sender]].shares > 0, "not a delegate");
        _;
    }

    modifier onlyAdmin {
        require(isAdmin(_msgSender()), "caller does not have the Admin role");
        _;
    }


    // *********
    // FUNCTIONS
    // *********
    constructor(
        address summoner,
        address _peepsWallet,
        address[] memory _approvedTokens,
        uint256 _periodDuration,
        uint256 _votingPeriodLength,
        uint256 _gracePeriodLength,
        uint256 _emergencyExitWait,
        uint256 _proposalDeposit,
        uint256 _dilutionBound,
        uint256 _processingReward,
        uint256 _minDonation,
        uint256 _adminFee,
        bool _canQuit
    ) public {
        require(summoner != address(0), "summoner cannot be 0");
        require(_periodDuration > 0, "period duration cannot be 0");
        require(_votingPeriodLength > 0, "voting period length cannot be 0");
        require(_votingPeriodLength <= MAX_VOTING_PERIOD_LENGTH, "voting period length exceeds limit");
        require(_gracePeriodLength <= MAX_GRACE_PERIOD_LENGTH, "grace period length exceeds limit");
        require(_emergencyExitWait > 0, "emergency exit wait cannot be 0");
        require(_dilutionBound > 0, "dilution bound cannot be 0");
        require(_dilutionBound <= MAX_DILUTION_BOUND, "dilution bound exceeds limit");
        require(_approvedTokens.length > 0, "need at least one approved token");
        require(_proposalDeposit >= _processingReward, "proposal deposit cannot be smaller than processing reward");


        //placed here to avoid a stack to deep error
        emit SummonComplete(summoner, _approvedTokens, now, _periodDuration, _votingPeriodLength, _gracePeriodLength, _proposalDeposit,  _processingReward);

        // first approved token is the deposit token, so choice will be between ETH or DAI
        depositToken = _approvedTokens[0];

        //check depositToken and add it to the tokenWhitelist
        for (uint256 i = 0; i < _approvedTokens.length; i++) {
            require(_approvedTokens[i] != address(0), "_approvedToken cannot be 0");
            require(!tokenWhitelist[_approvedTokens[i]], "duplicate approved token");
            tokenWhitelist[_approvedTokens[i]] = true;
            approvedTokens.push(_approvedTokens[i]);
        }
        //make sure that the depositToken is counted in the GuildBankTokens list
        totalGuildBankTokens += 1;

        //set default parameters
        peepsWallet = _peepsWallet;
        periodDuration = _periodDuration;
        votingPeriodLength = _votingPeriodLength;
        gracePeriodLength = _gracePeriodLength;
        emergencyExitWait = _emergencyExitWait;
        proposalDeposit = _proposalDeposit;
        dilutionBound = _dilutionBound;
        processingReward = _processingReward;
        minDonation = _minDonation;
        adminFee = _adminFee;
        canQuit = _canQuit;

        summoningTime = now;

        //adds summoner as first member with 1 share
        members[summoner] = Member(summoner, 1, 0, 0, true, _canQuit);
        memberAddressByDelegateKey[summoner] = summoner;
        totalShares = 1;

        //adds summoner as Admin so they can add future admins
        _addAdmin(summoner);

    }

    // ******************
    // PROPOSAL FUNCTIONS
    // ******************

     function submitProposal(
        address applicant,
        uint256 sharesRequested,
        uint256 tributeOffered,
        address tributeToken,
        uint256 paymentRequested,
        address paymentToken,
        string memory details
    ) public nonReentrant returns (uint256 proposalId) {
        require(sharesRequested <= MAX_NUMBER_OF_SHARES, "too many shares requested");
        require(tokenWhitelist[tributeToken], "tributeToken is not whitelisted");
        require(tokenWhitelist[paymentToken], "payment is not whitelisted");
        require(applicant != address(0), "applicant cannot be 0");
        require(applicant != GUILD && applicant != ESCROW && applicant != TOTAL, "applicant address cannot be reserved");
        require(members[applicant].jailed == 0, "proposal applicant must not be jailed");

        // collect proposal deposit from proposal submitter
        require(IERC20(depositToken).transferFrom(msg.sender, address(this), proposalDeposit), "proposal deposit token transfer failed");
        unsafeAddToBalance(ESCROW, depositToken, proposalDeposit);

        // collect tribute from proposer and store it in the Moloch until the proposal is processed
        require(IERC20(tributeToken).transferFrom(msg.sender, address(this), tributeOffered), "tribute token transfer failed");
        unsafeAddToBalance(ESCROW, tributeToken, tributeOffered);

        bool[5] memory flags; // [sponsored, processed, didPass, cancelled, whitelist, guildkick]

        _submitProposal(applicant, sharesRequested, tributeOffered, tributeToken, paymentRequested, paymentToken, details, flags);
        return proposalCount - 1; // return proposalId - contracts calling submit might want it
    }

    function submitGuildKickProposal(address memberToKick, string memory details) public nonReentrant returns (uint256 proposalId) {
        Member memory member = members[memberToKick];

        require(member.shares > 0, "member must have at least one share");
        require(members[memberToKick].jailed == 0, "member must not already be jailed");

        bool[5] memory flags; // [sponsored, processed, didPass, cancelled, whitelist, guildkick]
        flags[4] = true; // guild kick

        _submitProposal(memberToKick, 0, 0, address(0), 0, address(0), details, flags);
        return proposalCount - 1;
    }

    function _submitProposal(
        address applicant,
        uint256 sharesRequested,
        uint256 tributeOffered,
        address tributeToken,
        uint256 paymentRequested,
        address paymentToken,
        string memory details,
        bool[5] memory flags
    ) internal {
        Proposal memory proposal = Proposal({
            applicant : applicant,
            proposer : msg.sender,
            sponsor : address(0),
            sharesRequested : sharesRequested,
            tributeOffered : tributeOffered,
            tributeToken : tributeToken,
            paymentRequested : paymentRequested,
            paymentToken : paymentToken,
            startingPeriod : 0,
            yesVotes : 0,
            noVotes : 0,
            flags : flags,
            details : details,
            maxTotalSharesAtYesVote : 0
        });

        proposals[proposalCount] = proposal;
        address memberAddress = memberAddressByDelegateKey[msg.sender];
        // NOTE: argument order matters to avoid stack too deep
        emit SubmitProposal(applicant, sharesRequested, tributeOffered, tributeToken, paymentRequested, paymentToken, details, flags, proposalCount, memberAddress);
        proposalCount += 1;
    }

    function sponsorProposal(uint256 proposalId) public nonReentrant onlyAdmin {

        Proposal storage proposal = proposals[proposalId];

        require(proposal.proposer != address(0), 'proposal must have been proposed');
        require(!proposal.flags[0], "proposal has already been sponsored");
        require(!proposal.flags[3], "proposal has been cancelled");
        require(members[proposal.applicant].jailed == 0, "proposal applicant must not be jailed");

        if (proposal.flags[4]) {
            require(!proposedToKick[proposal.applicant], 'already proposed to kick');
            proposedToKick[proposal.applicant] = true;
        }

        // compute startingPeriod for proposal
        uint256 startingPeriod = max(
            getCurrentPeriod(),
            proposalQueue.length == 0 ? 0 : proposals[proposalQueue[proposalQueue.length.sub(1)]].startingPeriod
        ).add(1);

        proposal.startingPeriod = startingPeriod;

        address memberAddress = memberAddressByDelegateKey[msg.sender];
        proposal.sponsor = memberAddress;

        proposal.flags[0] = true; // sponsored

        // append proposal to the queue
        proposalQueue.push(proposalId);

        emit SponsorProposal(msg.sender, memberAddress, proposalId, proposalQueue.length.sub(1), startingPeriod);
    }

    function submitVote(uint256 proposalIndex, uint8 uintVote) public nonReentrant onlyDelegate {
        address memberAddress = memberAddressByDelegateKey[msg.sender];
        Member storage member = members[memberAddress];

        require(proposalIndex < proposalQueue.length, "proposal does not exist");
        Proposal storage proposal = proposals[proposalQueue[proposalIndex]];

        //0 for null, 1 for yes, 2 for no
        require(uintVote < 3, "uintVote must be less than 3");
        Vote vote = Vote(uintVote);

        require(proposal.flags[0], "proposal has not been sponsored");
        require(getCurrentPeriod() >= proposal.startingPeriod, "voting period has not started");
        require(!hasVotingPeriodExpired(proposal.startingPeriod), "voting period has expired");
        require(proposal.votesByMember[memberAddress] == Vote.Null, "member has already voted on this proposal");
        require(vote == Vote.Yes || vote == Vote.No, "vote must be either Yes or No");

        // store vote
        proposal.votesByMember[memberAddress] = vote;

        // count vote
        if (vote == Vote.Yes) {
            proposal.yesVotes = proposal.yesVotes.add(member.shares);

            // set highest index (latest) yes vote - must be processed for member to ragequit
            if (proposalIndex > member.highestIndexYesVote) {
                member.highestIndexYesVote = proposalIndex;
            }

            // set maximum of total shares encountered at a yes vote - used to bound dilution for yes voters
            if (totalShares > proposal.maxTotalSharesAtYesVote) {
                proposal.maxTotalSharesAtYesVote = totalShares;
            }

        } else if (vote == Vote.No) {
            proposal.noVotes = proposal.noVotes.add(member.shares);
        }

        emit SubmitVote(proposalIndex, msg.sender, memberAddress, uintVote);
    }

    function processProposal(uint256 proposalIndex) public nonReentrant onlyAdmin {
        _validateProposalForProcessing(proposalIndex);

        uint256 proposalId = proposalQueue[proposalIndex];
        Proposal storage proposal = proposals[proposalId];

        require(!proposal.flags[4], "must be a standard proposal");

        proposal.flags[1] = true; // processed

        bool didPass = _didPass(proposalIndex);

        // Make the proposal fail if the new total number of shares and loot exceeds the limit
        if (totalShares.add(proposal.sharesRequested) > MAX_NUMBER_OF_SHARES) {
            didPass = false;
        }

        // Make the proposal fail if it is requesting more tokens as payment than the available guild bank balance
        if (proposal.paymentRequested > userTokenBalances[GUILD][proposal.paymentToken]) {
            didPass = false;
        }

        // Make the proposal fail if it would result in too many tokens with non-zero balance in guild bank
        if (proposal.tributeOffered > 0 && userTokenBalances[GUILD][proposal.tributeToken] == 0 && totalGuildBankTokens >= MAX_TOKEN_GUILDBANK_COUNT) {
           didPass = false;
        }

        // PROPOSAL PASSED
        if (didPass) {
            proposal.flags[2] = true; // didPass

            // if the applicant is already a member, add to their existing shares & loot
            if (members[proposal.applicant].exists) {
                members[proposal.applicant].shares = members[proposal.applicant].shares.add(proposal.sharesRequested);

            // the applicant is a new member, create a new record for them
            } else {
                // if the applicant address is already taken by a member's delegateKey, reset it to their member address
                if (members[memberAddressByDelegateKey[proposal.applicant]].exists) {
                    address memberToOverride = memberAddressByDelegateKey[proposal.applicant];
                    memberAddressByDelegateKey[memberToOverride] = memberToOverride;
                    members[memberToOverride].delegateKey = memberToOverride;
                }

                // use applicant address as delegateKey by default
                members[proposal.applicant] = Member(proposal.applicant, proposal.sharesRequested, 0, 0, true, canQuit);
                memberAddressByDelegateKey[proposal.applicant] = proposal.applicant;
            }

            // mint new shares & loot
            totalShares = totalShares.add(proposal.sharesRequested);

            // if the proposal tribute is the first tokens of its kind to make it into the guild bank, increment total guild bank tokens
            if (userTokenBalances[GUILD][proposal.tributeToken] == 0 && proposal.tributeOffered > 0) {
                totalGuildBankTokens += 1;
            }

            unsafeInternalTransfer(ESCROW, GUILD, proposal.tributeToken, proposal.tributeOffered);
            unsafeInternalTransfer(GUILD, proposal.applicant, proposal.paymentToken, proposal.paymentRequested);

            // if the proposal spends 100% of guild bank balance for a token, decrement total guild bank tokens
            if (userTokenBalances[GUILD][proposal.paymentToken] == 0 && proposal.paymentRequested > 0) {
                totalGuildBankTokens -= 1;
            }

        // PROPOSAL FAILED
        } else {
            // return all tokens to the proposer (not the applicant, because funds come from proposer)
            unsafeInternalTransfer(ESCROW, proposal.proposer, proposal.tributeToken, proposal.tributeOffered);
        }

        _returnDeposit(proposal.proposer);

        emit ProcessProposal(proposalIndex, proposalId, didPass);
    }

function processGuildKickProposal(uint256 proposalIndex) public nonReentrant {
        _validateProposalForProcessing(proposalIndex);

        uint256 proposalId = proposalQueue[proposalIndex];
        Proposal storage proposal = proposals[proposalId];

        require(proposal.flags[4], "must be a guild kick proposal");

        proposal.flags[1] = true; // processed

        bool didPass = _didPass(proposalIndex);

        if (didPass) {
            proposal.flags[2] = true; // didPass
            Member storage member = members[proposal.applicant];
            member.jailed = proposalIndex;
            //rage quit members shares and return pro-rata guild funds to them.
            _ragequit(proposal.applicant, members[proposal.applicant].shares);

            member.shares = 0; // revoke all shares
        }

        proposedToKick[proposal.applicant] = false;

        _returnDeposit(proposal.sponsor);

        emit ProcessGuildKickProposal(proposalIndex, proposalId, didPass);
    }

    function _didPass(uint256 proposalIndex) internal returns (bool didPass) {
        Proposal memory proposal = proposals[proposalQueue[proposalIndex]];

        didPass = proposal.yesVotes > proposal.noVotes;

        // Make the proposal fail if the dilutionBound is exceeded
        if (totalShares.mul(dilutionBound) < proposal.maxTotalSharesAtYesVote) {
            didPass = false;
        }

        // Make the proposal fail if the applicant is jailed
        // - for standard proposals, we don't want the applicant to get any shares/loot/payment
        // - for guild kick proposals, we should never be able to propose to kick a jailed member (or have two kick proposals active), so it doesn't matter
        if (members[proposal.applicant].jailed != 0) {
            didPass = false;
        }

        return didPass;
    }

    function _validateProposalForProcessing(uint256 proposalIndex) internal view {
        require(proposalIndex < proposalQueue.length, "proposal does not exist");
        Proposal memory proposal = proposals[proposalQueue[proposalIndex]];

        require(getCurrentPeriod() >= proposal.startingPeriod.add(votingPeriodLength).add(gracePeriodLength), "proposal is not ready to be processed");
        require(proposal.flags[1] == false, "proposal has already been processed");
        require(proposalIndex == 0 || proposals[proposalQueue[proposalIndex.sub(1)]].flags[1], "previous proposal must be processed");
    }

    function _returnDeposit(address sponsor) internal {
        unsafeInternalTransfer(ESCROW, msg.sender, depositToken, processingReward);
        unsafeInternalTransfer(ESCROW, sponsor, depositToken, proposalDeposit.sub(processingReward));
    }


    function ragequit(uint256 sharesToBurn) public nonReentrant onlyMember {
        _ragequit(msg.sender, sharesToBurn);
    }


    function _ragequit(address memberAddress, uint256 sharesToBurn) internal {

        uint256 initialTotalShares = totalShares;

        Member storage member = members[memberAddress];

        require(member.canQuit  == true, "member must get admin approval to quit");
        require(member.shares >= sharesToBurn, "insufficient shares");

        require(canRagequit(member.highestIndexYesVote), "cannot ragequit until highest index proposal member voted YES on is processed");

        // burn shares
        member.shares = member.shares.sub(sharesToBurn);
        totalShares = totalShares.sub(sharesToBurn);

        // instruct GUILD to transfer fair share of tokens to the ragequitter
        for (uint256 i = 0; i < approvedTokens.length; i++) {
            uint256 amountToRagequit = fairShare(userTokenBalances[GUILD][approvedTokens[i]], sharesToBurn, initialTotalShares);
            if (amountToRagequit > 0) { // gas optimization to allow a higher maximum token limit
                // deliberately not using safemath here to keep overflows from preventing the function execution (which would break ragekicks)
                // if a token overflows, it is because the supply was artificially inflated to oblivion, so we probably don't care about it anyways
                userTokenBalances[GUILD][approvedTokens[i]] -= amountToRagequit;
                userTokenBalances[memberAddress][approvedTokens[i]] += amountToRagequit;
            }
        }

        emit Ragequit(msg.sender, sharesToBurn);
    }

        function withdrawBalance(address token, uint256 amount) public nonReentrant {
        _withdrawBalance(token, amount);
    }

    function withdrawBalances(address[] memory tokens, uint256[] memory amounts, bool max) public nonReentrant {
        require(tokens.length == amounts.length, "tokens and amounts arrays must be matching lengths");

        for (uint256 i=0; i < tokens.length; i++) {
            uint256 withdrawAmount = amounts[i];
            if (max) { // withdraw the maximum balance
                withdrawAmount = userTokenBalances[msg.sender][tokens[i]];
            }

            _withdrawBalance(tokens[i], withdrawAmount);
        }
    }

    function _withdrawBalance(address token, uint256 amount) internal {
        require(userTokenBalances[msg.sender][token] >= amount, "insufficient balance");
        unsafeSubtractFromBalance(msg.sender, token, amount);
        require(IERC20(token).transfer(msg.sender, amount), "transfer failed");
        emit Withdraw(msg.sender, token, amount);
    }

    function cancelProposal(uint256 proposalId) public nonReentrant {
        Proposal storage proposal = proposals[proposalId];
        require(!proposal.flags[0], "proposal has already been sponsored");
        require(!proposal.flags[3], "proposal has already been cancelled");
        require(msg.sender == proposal.proposer, "solely the proposer can cancel");

        proposal.flags[3] = true; // cancelled

        unsafeInternalTransfer(ESCROW, proposal.proposer, proposal.tributeToken, proposal.tributeOffered);
        emit CancelProposal(proposalId, msg.sender);
    }

    function updateDelegateKey(address newDelegateKey) public onlyMember {
        require(newDelegateKey != address(0), "newDelegateKey cannot be 0");

        // skip checks if member is setting the delegate key to their member address
        if (newDelegateKey != msg.sender) {
            require(!members[newDelegateKey].exists, "cannot overwrite existing members");
            require(!members[memberAddressByDelegateKey[newDelegateKey]].exists, "cannot overwrite existing delegate keys");
        }

        Member storage member = members[msg.sender];
        memberAddressByDelegateKey[member.delegateKey] = address(0);
        memberAddressByDelegateKey[newDelegateKey] = msg.sender;
        member.delegateKey = newDelegateKey;

        emit UpdateDelegateKey(msg.sender, newDelegateKey);
    }

    // ****************
    // ADMIN FUNCTIONS
    // ****************

        function  addMember (address _newMemberAddress, uint256 _tributeAmount) onlyAdmin public returns(bool) {

            require(_newMemberAddress != address(0), "new member applicant cannot be 0");
            require(_tributeAmount >= minDonation, "applicant cannot give less than min donation");

            //rounds down to nearest number of shares based on tribute offered and minimum donation
             uint256 shares = (_tributeAmount) / (minDonation);

            //peeps fee calculations and pay fee to to peepsWallet address
             uint256 decimalFactor = 10**uint256(18);
             uint256 peepsFee = (_tributeAmount.mul(decimalFactor)).div((adminFee*decimalFactor));
            //uint256 tributeAmount = _tributeAmount.sub(peepsFee);


            if (members[_newMemberAddress].exists) {
                members[_newMemberAddress].shares = members[_newMemberAddress].shares.add(shares);
            // the applicant is a new member, create a new record for them
            } else {
            // if the applicant address is already taken by a member's delegateKey, reset it to their member address
            if (members[memberAddressByDelegateKey[_newMemberAddress]].exists) {
                address memberToOverride = memberAddressByDelegateKey[_newMemberAddress];
                memberAddressByDelegateKey[memberToOverride] = memberToOverride;
                members[memberToOverride].delegateKey = memberToOverride;
                }
                // use applicant address as delegateKey by default
                members[_newMemberAddress] = Member(_newMemberAddress, shares, 0, 0, true, canQuit);
                memberAddressByDelegateKey[_newMemberAddress] = _newMemberAddress;
            }

            //increase total contributed
            totalDepositTokens = totalDepositTokens.add(_tributeAmount);

            //increase total shares
            totalShares = totalShares.add(shares);

            //transfer donation to GUILD and then from GUILD to Peeps
            require(IERC20(depositToken).transferFrom(_newMemberAddress, address(this), _tributeAmount), "donation transfer failed");

            //update DAO accounting
            unsafeAddToBalance(GUILD, depositToken, _tributeAmount);
            userTokenBalances[GUILD][depositToken] -= peepsFee;
            unsafeInternalTransfer(GUILD, peepsWallet, depositToken, peepsFee);
            userTokenBalances[peepsWallet][depositToken] += peepsFee;

            //withdraw platform fees on donation
            _feeWithdraw(depositToken, peepsFee);

            //emit member added event
            emit MemberAdded(_newMemberAddress, _tributeAmount, shares);
        }

    //sends peepsFee to peepsWallet after donation is made
    //@dev prevents peepsWallet from manually having to call withdraw on regular intervals
    function _feeWithdraw(address token, uint256 amount) internal {
        require(userTokenBalances[peepsWallet][token] >= amount, "insufficient balance");
        unsafeSubtractFromBalance(peepsWallet, token, amount);
        require(IERC20(token).transfer(peepsWallet, amount), "transfer failed");
        emit feeWithdraw(peepsWallet, token, amount);
    }

    //Add admin functions, summoner is set as the original admin
    //No renounce admin function, because it's necessary to have at least one admin at all times for DAO to function.

    function addAdmin(address account) public onlyAdmin {
        _addAdmin(account);
    }

    function _addAdmin(address account) internal {
        _admins.add(account);
        emit AdminAdded(account);
    }

    function removeAdmin(address account) public onlyAdmin {
        _removeAdmin(account);
    }

    function _removeAdmin(address account) internal {
        _admins.remove(account);
        emit AdminRemoved(account);
    }

    //admin function to allow member to ragequit with permission
    function approveQuit(address memberAddress) public onlyAdmin {
         Member storage member = members[memberAddress];
        //require member not to already have quit privileges
        require(member.canQuit  == false, "member can already quit");
        //set member to quit
        member.canQuit = (member.canQuit = true);

        emit CanQuit(memberAddress);
    }

    //allows admins to add additional types of ERC20 tokens to the guild bank
        function addWhitelistedToken(address _tokenToWhitelist) public onlyAdmin returns(bool) {
        require(_tokenToWhitelist != address(0), "must provide token address");
        require(!tokenWhitelist[_tokenToWhitelist], "cannot already have whitelisted the token");
        require(totalGuildBankTokens < MAX_TOKEN_GUILDBANK_COUNT, 'cannot add new tokens - guildbank is full');


        tokenWhitelist[address(_tokenToWhitelist)] = true;
        approvedTokens.push(_tokenToWhitelist);

        emit TokenAdded(_tokenToWhitelist);
    }


    // ****************
    // GETTER FUNCTIONS
    // ****************

    function max(uint256 x, uint256 y) internal pure returns (uint256) {
        return x >= y ? x : y;
    }

    function getCurrentPeriod() public view returns (uint256) {
        return now.sub(summoningTime).div(periodDuration);
    }

    function getProposalQueueLength() public view returns (uint256) {
        return proposalQueue.length;
    }

    // can only ragequit if the latest proposal you voted YES on has been processed
    function canRagequit(uint256 highestIndexYesVote) public view returns (bool) {
        require(highestIndexYesVote < proposalQueue.length, "cannot rage quit until highestIndexYesVote is less than proposal queue");
        return proposals[proposalQueue[highestIndexYesVote]].flags[1]; // processed
    }

    function hasVotingPeriodExpired(uint256 startingPeriod) public view returns (bool) {
        return getCurrentPeriod() >= startingPeriod.add(votingPeriodLength);
    }

    function getMemberProposalVote(address memberAddress, uint256 proposalIndex) public view returns (Vote) {
        require(members[memberAddress].exists, "member does not exist");
        require(proposalIndex < proposalQueue.length, "proposal does not exist");
        return proposals[proposalQueue[proposalIndex]].votesByMember[memberAddress];
    }

    function isAdmin(address account) public view returns (bool) {
        return _admins.has(account);
    }

        /***************
    HELPER FUNCTIONS
    ***************/
    function unsafeAddToBalance(address user, address token, uint256 amount) internal {
        userTokenBalances[user][token] += amount;
        userTokenBalances[TOTAL][token] += amount;
    }

    function unsafeSubtractFromBalance(address user, address token, uint256 amount) internal {
        userTokenBalances[user][token] -= amount;
        userTokenBalances[TOTAL][token] -= amount;
    }

    function unsafeInternalTransfer(address from, address to, address token, uint256 amount) internal {
        unsafeSubtractFromBalance(from, token, amount);
        unsafeAddToBalance(to, token, amount);
    }

    function fairShare(uint256 balance, uint256 shares, uint256 totalShares) internal pure returns (uint256) {
        require(totalShares != 0);

        if (balance == 0) { return 0; }

        uint256 prod = balance * shares;

        if (prod / balance == shares) { // no overflow in multiplication above?
            return prod / totalShares;
        }

        return (balance / totalShares) * shares;
    }
}
