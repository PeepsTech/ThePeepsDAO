pragma solidity ^0.5.14;

import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/math/SafeMath.sol";
import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/token/ERC20/IERC20.sol";
import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/ownership/Ownable.sol";
import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/access/Roles.sol";
import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/utils/ReentrancyGuard.sol";

// *******************
// GuildBank Contract
// *******************

/*GuildBank is created when a new PeepsMoloch is launched,
so interacting with the GuildBank should be done by referencing the
GuildBank associated w/ that PeepsMoloch */

contract GuildBank  {
    address public owner;

    constructor () public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    event Withdrawal(address indexed receiver, address indexed tokenAddress, uint256 amount);

    function withdraw(address receiver, uint256 shares, uint256 totalShares, IERC20[] memory approvedTokens) public onlyOwner returns (bool) {
        for (uint256 i = 0; i < approvedTokens.length; i++) {
            uint256 amount = fairShare(approvedTokens[i].balanceOf(address(this)), shares, totalShares);
            emit Withdrawal(receiver, address(approvedTokens[i]), amount);
            require(approvedTokens[i].transfer(receiver, amount));
        }
        return true;
    }

    function withdrawToken(IERC20 token, address receiver, uint256 amount) public onlyOwner returns (bool) {
        emit Withdrawal(receiver, address(token), amount);
        return token.transfer(receiver, amount);
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
    bool public canQuit;

    IERC20 public depositToken; // reference to the deposit token
    GuildBank public guildBank; // guild bank contract reference

    // HARD-CODED LIMITS
    // These numbers are quite arbitrary; they are small enough to avoid overflows when doing calculations
    // with periods or shares, yet big enough to not limit reasonable use cases.
    uint256 constant MAX_VOTING_PERIOD_LENGTH = 10**18; // maximum length of voting period
    uint256 constant MAX_GRACE_PERIOD_LENGTH = 10**18; // maximum length of grace period
    uint256 constant MAX_DILUTION_BOUND = 10**18; // maximum dilution bound
    uint256 constant MAX_NUMBER_OF_SHARES = 10**18; // maximum number of shares that can be minted

    // ***************
    // EVENTS
    // ***************
    event SubmitProposal(uint256 proposalIndex, address indexed delegateKey, address indexed memberAddress, address indexed applicant,uint256 tributeOffered, address tributeToken, uint256 sharesRequested, address tokenToWhitelist, address memberToKick, uint256 paymentRequested, address paymentToken);
    event SubmitVote(uint256 indexed proposalQueueIndex, address indexed delegateKey, address indexed memberAddress, uint8 uintVote);
    event Ragequit(address indexed memberAddress, uint256 sharesToBurn, address[] tokenList);
    event CancelProposal(uint256 indexed proposalIndex, address applicantAddress);
    event UpdateDelegateKey(address indexed memberAddress, address newDelegateKey);
    event ProcessProposal(uint256 indexed proposalQueueIndex, address indexed applicant, address indexed memberAddress, uint256 tributeOffered, uint256 sharesRequested, bool didPass);
    event SponsorProposal(address indexed delegateKey, address indexed memberAddress, uint256 proposalIndex, uint256 proposalQueueIndex, uint256 startingPeriod);
    event SummonComplete(address indexed summoner, uint256 shares);
    event MemberAdded(address indexed _newMemberAddress, uint256 _tributeAmount, uint256 _shares);
    event AdminAdded(address indexed account);
    event AdminRemoved(address indexed account);
    event CanQuit(address indexed member);
    event TokenAdded (address indexed _tokenToWhitelist);

    // *******************
    // INTERNAL ACCOUNTING
    // *******************
    uint256 public proposalCount = 0; // total proposals submitted
    uint256 public totalShares = 0; // total shares across all members
    uint256 public totalContributed = 0; // total member contributions to guild bank
    uint256 public totalSharesRequested = 0; // total shares that have been requested in unprocessed proposals

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
        IERC20 tributeToken; // token being offered as tribute
        uint256 paymentRequested; // the payments requested for each applicant
        IERC20 paymentToken; // token to send payment in
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
    IERC20[] public approvedTokens; //deployed version will set to be only ETH or DAI.

    mapping (address => bool) public proposedToKick; // true if a member has been proposed to be kicked (to avoid duplicate guild kick proposals)

    mapping (address => Member) public members;
    mapping (address => address) public memberAddressByDelegateKey;
    address[] public memberAccts;

    Roles.Role private _admins;

    // proposals by ID
    mapping (uint256 => Proposal) public proposals;

    // the queue of proposals (only store a reference by the proposal id)
    uint256[] public proposalQueue;

    // *********
    // MODIFIERS
    // *********
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
        address[] memory _approvedTokens,
        uint256 _periodDuration,
        uint256 _votingPeriodLength,
        uint256 _gracePeriodLength,
        uint256 _emergencyExitWait,
        uint256 _proposalDeposit,
        uint256 _dilutionBound,
        uint256 _processingReward,
        uint256 _minDonation,
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

        // first approved token is the deposit token, so choice will be between ETH or DAI
        depositToken = IERC20(_approvedTokens[0]);

        for (uint256 i=0; i < _approvedTokens.length; i++) {
          require(_approvedTokens[i] != address(0), "approvedToken cannot be 0");
          require(!tokenWhitelist[_approvedTokens[i]], "duplicate approved token");
          tokenWhitelist[_approvedTokens[i]] = true;
          approvedTokens.push(IERC20(_approvedTokens[i]));
          }

        guildBank = new GuildBank();

        periodDuration = _periodDuration;
        votingPeriodLength = _votingPeriodLength;
        gracePeriodLength = _gracePeriodLength;
        emergencyExitWait = _emergencyExitWait;
        proposalDeposit = _proposalDeposit;
        dilutionBound = _dilutionBound;
        processingReward = _processingReward;
        minDonation = _minDonation;
        canQuit = _canQuit;

        summoningTime = now;

        members[summoner] = Member(summoner, 1, 0, 0, true, _canQuit);
        memberAddressByDelegateKey[summoner] = summoner;
        totalShares = 1;
        _addAdmin(summoner);

        emit SummonComplete(summoner, 1);
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
    )
        public nonReentrant
    {
        require(tokenWhitelist[tributeToken], "tribute token is not whitelisted");
        require(tokenWhitelist[paymentToken], "payment token is not whitelisted");
        require(members[applicant].jailed == 0, "proposal applicant must not be jailed");
        require(applicant != address(0), "applicant cannot be 0");

        // collect tribute from applicant and store it in the PeepsMoloch until the proposal is processed
        require(IERC20(tributeToken).transferFrom(msg.sender, address(this), tributeOffered), "tribute token transfer failed");

        bool[5] memory flags;

        // create proposal...
        Proposal memory proposal = Proposal({
            applicant: applicant,
            proposer: msg.sender,
            sponsor: address(0),
            sharesRequested: sharesRequested,
            tributeOffered: tributeOffered,
            tributeToken: IERC20(tributeToken),
            paymentRequested: paymentRequested,
            paymentToken: IERC20(paymentToken),
            startingPeriod: 0,
            yesVotes: 0,
            noVotes: 0,
            flags: flags,
            details: details,
            maxTotalSharesAtYesVote: 0
        });

        proposals[proposalCount] = proposal; // save proposal by its id

        address memberAddress = memberAddressByDelegateKey[msg.sender];
        emit SubmitProposal(proposalCount, msg.sender, memberAddress, applicant, tributeOffered, tributeToken, sharesRequested, address(0), address(0), paymentRequested, paymentToken);

        proposalCount += 1; // increment proposal counter

    }

    function submitGuildKickProposal(address memberToKick, string memory details) public nonReentrant onlyMember {
        require(members[memberToKick].shares > 0, "member must have at least one share");
        require(members[memberToKick].jailed == 0, "member must not already be jailed");


        bool[5] memory flags;
        flags[4] = true; // guild kick proposal = true

        // create proposal ...
        Proposal memory proposal = Proposal({
            applicant: memberToKick, // applicant = memberToKick
            proposer: msg.sender,
            sponsor: address(0),
            sharesRequested: 0,
            tributeOffered: 0,
            tributeToken: IERC20(address(0)),
            paymentRequested: 0,
            paymentToken: IERC20(address(0)),
            startingPeriod: 0,
            yesVotes: 0,
            noVotes: 0,
            flags: flags,
            details: details,
            maxTotalSharesAtYesVote: 0
        });

        proposals[proposalCount] = proposal; // save proposal by its id

        address memberAddress = memberAddressByDelegateKey[msg.sender];
        emit SubmitProposal(proposalCount, msg.sender, memberAddress, address(0), 0, address(0), 0, address(0), memberToKick, 0, address(0));

        proposalCount += 1; // increment proposal counter

    }

    function sponsorProposal(uint256 proposalId) public nonReentrant onlyAdmin {
        // collect proposal deposit from proposer and store it in the PeepsMoloch until the proposal is processed
        require(depositToken.transferFrom(msg.sender, address(this), proposalDeposit), "proposal deposit token transfer failed");

        Proposal storage proposal = proposals[proposalId];

        require(proposal.proposer != address(0), "proposal must have been proposed");
        require(!proposal.flags[0], "proposal has already been sponsored");
        require(!proposal.flags[3], "proposal has been cancelled");
        require(members[proposal.applicant].jailed == 0, "proposal applicant must not be jailed");


        // gkick proposal
        if (proposal.flags[4]) {
            require(!proposedToKick[proposal.applicant], "already proposed to kick");
            proposedToKick[proposal.applicant] = true;

        // standard proposal
        } else {
            // Make sure we won't run into overflows when doing calculations with shares.
            // Note that totalShares + totalSharesRequested + sharesRequested is an upper bound
            // on the number of shares that can exist until this proposal has been processed.
            require(totalShares.add(totalSharesRequested).add(proposal.sharesRequested) <= MAX_NUMBER_OF_SHARES, "too many shares requested");
            totalSharesRequested = totalSharesRequested.add(proposal.sharesRequested);
        }

        // compute startingPeriod for proposal
        uint256 startingPeriod = max(
            getCurrentPeriod(),
            proposalQueue.length == 0 ? 0 : proposals[proposalQueue[proposalQueue.length.sub(1)]].startingPeriod
        ).add(1);

        proposal.startingPeriod = startingPeriod;

        address memberAddress = memberAddressByDelegateKey[msg.sender];
        proposal.sponsor = memberAddress;
        proposal.flags[0] = true;

        // ... and append it to the queue by its id
        proposalQueue.push(proposalId);

        uint256 proposalQueueIndex = proposalQueue.length.sub(1);
        emit SponsorProposal(msg.sender, memberAddress, proposalId, proposalQueueIndex, startingPeriod);

    }

    function submitVote(uint256 proposalIndex, uint8 uintVote) public nonReentrant onlyDelegate {
        address memberAddress = memberAddressByDelegateKey[msg.sender];
        Member storage member = members[memberAddress];

        require(proposalIndex < proposalQueue.length, "proposal does not exist");
        Proposal storage proposal = proposals[proposalQueue[proposalIndex]];

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
        require(proposalIndex < proposalQueue.length, "proposal does not exist");
        Proposal storage proposal = proposals[proposalQueue[proposalIndex]];

        require(getCurrentPeriod() >= proposal.startingPeriod.add(votingPeriodLength).add(gracePeriodLength), "proposal is not ready to be processed");
        require(proposal.flags[1] == false, "proposal has already been processed");
        require(proposalIndex == 0 || proposals[proposalQueue[proposalIndex.sub(1)]].flags[1], "previous proposal must be processed");

        proposal.flags[1] = true;
        totalSharesRequested = totalSharesRequested.sub(proposal.sharesRequested);

        bool didPass = proposal.yesVotes > proposal.noVotes;

        // If emergencyExitWait has passed from when this proposal *should* have been able to be processed, skip all effects
        bool emergencyProcessing = false;
        if (getCurrentPeriod() >= proposal.startingPeriod.add(votingPeriodLength).add(gracePeriodLength).add(emergencyExitWait)) {
            emergencyProcessing = true;
            didPass = false;
        }

        // Make the proposal fail if the dilutionBound is exceeded
        if (totalShares.mul(dilutionBound) < proposal.maxTotalSharesAtYesVote) {
            didPass = false;
        }

        // Make sure there is enough tokens for payments, or auto-fail
        if (proposal.paymentRequested >= proposal.paymentToken.balanceOf(address(guildBank))) {
            didPass = false;
        }

         if (members[proposal.applicant].jailed != 0) {
            didPass = false;
        }

        // PROPOSAL PASSED
        if (didPass) {

            proposal.flags[2] = true; // didPass = true

            // guild kick proposal passed, ragequit 100% of the member's shares
             if (proposal.flags[4]) {
                 Member storage member = members[proposal.applicant];
                 member.jailed = proposalIndex;
                _ragequit(proposal.applicant, members[proposal.applicant].shares, approvedTokens);

            // standard proposal passed, collect tribute, send payment, mint shares
            } else {
                // if the applicant is already a member, add to their existing shares
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

                // mint new shares, if requested
                totalShares = totalShares.add(proposal.sharesRequested);

                // transfer tribute tokens to guild bank, if provided
                require(
                    proposal.tributeToken.transfer(address(guildBank), proposal.tributeOffered),
                    "token transfer to guild bank failed"
                );

                totalContributed = totalContributed.add(proposal.tributeOffered);

                // transfer payment tokens to applicant for grants
                require(
                    guildBank.withdrawToken(proposal.paymentToken, proposal.applicant, proposal.paymentRequested),
                    "token payment to applicant failed"
                );
            }

        // PROPOSAL FAILED
        } else {
            // Don't return applicant tokens if we are in emergency processing - likely the tokens are broken
                // return all tokens to the proposer
                require(
                    proposal.tributeToken.transfer(proposal.proposer, proposal.tributeOffered),
                    "failing vote token transfer failed"
                );
        }

        // if guild kick proposal, remove member from list of members proposed to be kicked
        if (proposal.flags[4]) {
            proposedToKick[proposal.applicant] = false;
        }

        // send msg.sender the processingReward
        require(
            depositToken.transfer(msg.sender, processingReward),
            "failed to send processing reward to msg.sender"
        );

        // return deposit to sponsor (subtract processing reward)
        require(
            depositToken.transfer(proposal.sponsor, proposalDeposit.sub(processingReward)),
            "failed to return proposal deposit to sponsor"
        );

        emit ProcessProposal(proposalIndex, proposal.applicant, proposal.proposer, proposal.tributeOffered, proposal.sharesRequested, didPass);
    }

    function ragequit(uint256 sharesToBurn) public nonReentrant onlyMember {
        _ragequit(msg.sender, sharesToBurn, approvedTokens);
    }


    function _ragequit(address memberAddress, uint256 sharesToBurn, IERC20[] memory _approvedTokens) internal {
        uint256 initialTotalShares = totalShares;

        Member storage member = members[memberAddress];

        require(member.canQuit  == true, "member must get admin approval to quit");

        require(member.shares >= sharesToBurn, "insufficient shares");

        require(canRagequit(member.highestIndexYesVote), "cannot ragequit until highest index proposal member voted YES on is processed");

        // burn shares
        member.shares = member.shares.sub(sharesToBurn);
        totalShares = totalShares.sub(sharesToBurn);

        // instruct guildBank to transfer fair share of tokens to the ragequitter
        require(
            guildBank.withdraw(memberAddress, sharesToBurn, initialTotalShares, _approvedTokens),
            "withdrawal of tokens from guildBank failed"
        );

          address[] memory tokenList = new address[](_approvedTokens.length);
             for (uint256 i=0; i < _approvedTokens.length; i++) {
             tokenList[i] = address(approvedTokens[i]);
        }
        emit Ragequit(msg.sender, sharesToBurn, tokenList);
    }

    function cancelProposal(uint256 proposalId) public {
        Proposal storage proposal = proposals[proposalId];
        require(!proposal.flags[0], "proposal has already been sponsored");
        require(msg.sender == proposal.proposer, "only the proposer can cancel");

        proposal.flags[3] = true; // cancelled

        require(
            proposal.tributeToken.transfer(proposal.proposer, proposal.tributeOffered),
            "failed to return tribute to proposer"
        );

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

    //@dev function to add a member without going through submit proposal process
    //TODO: automatically calculate number of shares issued based on minimum tribute where 1 share = min. donation amt.

        function  addMember (address _newMemberAddress, uint256 _tributeAmount) onlyAdmin public returns(bool) {

            require(_newMemberAddress != address(0), "new member applicant cannot be 0");

            //@dev rounds down to nearest number of shares based on tribute offered and minimum donation
            require(_tributeAmount >= minDonation, "applicant cannot give less than min donation");

               uint shares = (_tributeAmount) / (minDonation);

               if (members[_newMemberAddress].exists  == true) {
                //existing member makes another donation
                members[_newMemberAddress].shares = members[_newMemberAddress].shares.add(shares);
               } else {
                //new member makes first donation
                members[_newMemberAddress] = Member(_newMemberAddress, shares, 0, 0, true, canQuit);
                memberAddressByDelegateKey[_newMemberAddress] = _newMemberAddress;
                memberAccts.push(_newMemberAddress) -1;
               }

            //increase total contributed
            totalContributed = totalContributed.add(_tributeAmount);

            //increase total shares
            totalShares = totalShares.add(shares);

            //transfer donation to GuildBank
            require(depositToken.transferFrom(_newMemberAddress, address(guildBank), _tributeAmount), "tribute token transfer failed");

            //emit event
            emit MemberAdded(_newMemberAddress, _tributeAmount, shares);
        }

    //@Dev - add admin functions, summoner is set as the original admin
    //TODO - consider adding a renounce admin function

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

        tokenWhitelist[address(_tokenToWhitelist)] = true;
        approvedTokens.push(IERC20(_tokenToWhitelist));

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
}
