// SPDX-License-Identifier: BUSL-1.1
pragma solidity =0.8.12;

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@openzeppelin-upgrades/contracts/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin-upgrades/contracts/utils/AddressUpgradeable.sol";
import "@openzeppelin-upgrades/contracts/utils/math/MathUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import "../libraries/BeaconChainProofs.sol";
import "../libraries/BytesLib.sol";
import "../libraries/Endian.sol";

import "../interfaces/IETHPOSDeposit.sol";
import "../interfaces/IEigenPodManager.sol";
import "../interfaces/IEigenPod.sol";
import "../interfaces/IDelayedWithdrawalRouter.sol";
import "../interfaces/IPausable.sol";

import "./EigenPodPausingConstants.sol";

/**
 * @title The implementation contract used for restaking beacon chain ETH on EigenLayer
 * @author Layr Labs, Inc.
 * @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
 * @notice The main functionalities are:
 * - creating new ETH validators with their withdrawal credentials pointed to this contract
 * - proving from beacon chain state roots that withdrawal credentials are pointed to this contract
 * - proving from beacon chain state roots the balances of ETH validators with their withdrawal credentials
 *   pointed to this contract
 * - updating aggregate balances in the EigenPodManager
 * - withdrawing eth when withdrawals are initiated
 * @notice This EigenPod Beacon Proxy implementation adheres to the current Capella consensus specs
 * @dev Note that all beacon chain balances are stored as gwei within the beacon chain datastructures. We choose
 *   to account balances in terms of gwei in the EigenPod contract and convert to wei when making calls to other contracts
 */
contract EigenPod is IEigenPod, Initializable, ReentrancyGuardUpgradeable, EigenPodPausingConstants {
    using BytesLib for bytes;
    using SafeERC20 for IERC20;
    using BeaconChainProofs for *;

    // CONSTANTS + IMMUTABLES
    // @notice Internal constant used in calculations, since the beacon chain stores balances in Gwei rather than wei
    uint256 internal constant GWEI_TO_WEI = 1e9;

    /**
     * @notice Maximum "staleness" of a Beacon Chain state root against which `verifyBalanceUpdate` or `verifyWithdrawalCredentials` may be proven.
     * We can't allow "stale" roots to be used for restaking as the validator may have been slashed in a more updated beacon state root. 
     */
    uint256 internal constant VERIFY_BALANCE_UPDATE_WINDOW_SECONDS = 4.5 hours;

    /// @notice This is the beacon chain deposit contract
    IETHPOSDeposit public immutable ethPOS;

    /// @notice Contract used for withdrawal routing, to provide an extra "safety net" mechanism
    IDelayedWithdrawalRouter public immutable delayedWithdrawalRouter;

    /// @notice The single EigenPodManager for EigenLayer
    IEigenPodManager public immutable eigenPodManager;

    ///@notice The maximum amount of ETH, in gwei, a validator can have restaked in the eigenlayer
    uint64 public immutable MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR;

    /// @notice This is the genesis time of the beacon state, to help us calculate conversions between slot and timestamp
    uint64 public immutable GENESIS_TIME;

    // STORAGE VARIABLES
    /// @notice The owner of this EigenPod
    address public podOwner;

    /**
     * @notice The latest timestamp at which the pod owner withdrew the balance of the pod, via calling `withdrawBeforeRestaking`.
     * @dev This variable is only updated when the `withdrawBeforeRestaking` function is called, which can only occur before `hasRestaked` is set to true for this pod.
     * Proofs for this pod are only valid against Beacon Chain state roots corresponding to timestamps after the stored `mostRecentWithdrawalTimestamp`.
     */
    uint64 public mostRecentWithdrawalTimestamp;

    /// @notice the amount of execution layer ETH in this contract that is staked in EigenLayer (i.e. withdrawn from the Beacon Chain but not from EigenLayer),
    uint64 public withdrawableRestakedExecutionLayerGwei;

    /// @notice an indicator of whether or not the podOwner has ever "fully restaked" by successfully calling `verifyCorrectWithdrawalCredentials`.
    bool public hasRestaked;

    /// @notice This is a mapping of validatorPubkeyHash to timestamp to whether or not they have proven a withdrawal for that timestamp
    mapping(bytes32 => mapping(uint64 => bool)) public provenWithdrawal;

    /// @notice This is a mapping that tracks a validator's information by their pubkey hash
    mapping(bytes32 => ValidatorInfo) internal _validatorPubkeyHashToInfo;

    /// @notice This variable tracks any ETH deposited into this contract via the `receive` fallback function
    uint256 public nonBeaconChainETHBalanceWei;

     /// @notice This variable tracks the total amount of partial withdrawals claimed via merkle proofs prior to a switch to ZK proofs for claiming partial withdrawals
    uint64 public sumOfPartialWithdrawalsClaimedGwei;

    /// @notice number of validators proven to have withdrawal credentials pointed at this pod, minus
    /// the number of validators who have already proven full withdrawals from this pod.
    uint256 activeValidatorCount;
    
    /// @dev oracleTimestamp -> cached proven beaconStateRoot
    /// NOTE: We could take this even further, and cache all the way down to the validator tree
    mapping(uint64 => bytes32) cachedStateRoots;

    struct Checkpoint {
        uint24 proofsRemaining;
        uint232 eligibleBalance;
    }

    /// @dev If we have an active partial withdrawal checkpoint, `currentCheckpoint`
    ///      is the oracle timestamp being used to prove that checkpoint's validator set
    ///
    ///      This value can be used to look up additional checkpoint info in 
    ///      `validatorProven` below.
    uint64 currentCheckpointTimestamp;

    Checkpoint currentCheckpoint;

    /// @dev oracleTimestamp -> validator pubkeyHash -> valid proof
    mapping(uint64 => mapping(bytes32 => bool)) validatorProven;

    modifier onlyEigenPodManager() {
        require(msg.sender == address(eigenPodManager), "EigenPod.onlyEigenPodManager: not eigenPodManager");
        _;
    }

    modifier onlyEigenPodOwner() {
        require(msg.sender == podOwner, "EigenPod.onlyEigenPodOwner: not podOwner");
        _;
    }

    modifier hasNeverRestaked() {
        require(!hasRestaked, "EigenPod.hasNeverRestaked: restaking is enabled");
        _;
    }

    /// @notice checks that hasRestaked is set to true by calling activateRestaking()
    modifier hasEnabledRestaking() {
        require(hasRestaked, "EigenPod.hasEnabledRestaking: restaking is not enabled");
        _;
    }

    /// @notice Checks that `timestamp` is strictly greater than the value stored in `mostRecentWithdrawalTimestamp`
    modifier proofIsForValidTimestamp(uint64 timestamp) {
        require(
            timestamp > mostRecentWithdrawalTimestamp,
            "EigenPod.proofIsForValidTimestamp: beacon chain proof must be for timestamp after mostRecentWithdrawalTimestamp"
        );
        _;
    }

    /**
     * @notice Based on 'Pausable' code, but uses the storage of the EigenPodManager instead of this contract. This construction
     * is necessary for enabling pausing all EigenPods at the same time (due to EigenPods being Beacon Proxies).
     * Modifier throws if the `indexed`th bit of `_paused` in the EigenPodManager is 1, i.e. if the `index`th pause switch is flipped.
     */
    modifier onlyWhenNotPaused(uint8 index) {
        require(
            !IPausable(address(eigenPodManager)).paused(index),
            "EigenPod.onlyWhenNotPaused: index is paused in EigenPodManager"
        );
        _;
    }

    constructor(
        IETHPOSDeposit _ethPOS,
        IDelayedWithdrawalRouter _delayedWithdrawalRouter,
        IEigenPodManager _eigenPodManager,
        uint64 _MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR,
        uint64 _GENESIS_TIME
    ) {
        ethPOS = _ethPOS;
        delayedWithdrawalRouter = _delayedWithdrawalRouter;
        eigenPodManager = _eigenPodManager;
        MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR = _MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR;
        GENESIS_TIME = _GENESIS_TIME;
        _disableInitializers();
    }

    /// @notice Used to initialize the pointers to addresses crucial to the pod's functionality. Called on construction by the EigenPodManager.
    function initialize(address _podOwner) external initializer {
        require(_podOwner != address(0), "EigenPod.initialize: podOwner cannot be zero address");
        podOwner = _podOwner;
        /**
         * From the M2 deployment onwards, we are requiring that pods deployed are by default enabled with restaking
         * In prior deployments without proofs, EigenPods could be deployed with restaking disabled so as to allow
         * simple (proof-free) withdrawals.  However, this is no longer the case.  Thus going forward, all pods are
         * initialized with hasRestaked set to true.
         */
        hasRestaked = true;
        emit RestakingActivated(podOwner);
    }

    /// @notice payable fallback function that receives ether deposited to the eigenpods contract
    receive() external payable {
        nonBeaconChainETHBalanceWei += msg.value;
        emit NonBeaconChainETHReceived(msg.value);
    }

    /**
     * @dev Begin the partial withdrawal process by checkpointing the pod's current active validators
     *      and unaccounted-for balance.
     */
    function startPartialWithdrawal() external onlyEigenPodOwner() /**onlyWhenNotPaused*/ {
        uint256 eligibleBalance = 
            address(this).balance 
                - nonBeaconChainETHBalanceWei 
                - (withdrawableRestakedExecutionLayerGwei * GWEI_TO_WEI);
        require(eligibleBalance != 0, "No eligible balance to withdraw");

        // If we have no active validators, there are no additional steps needed!
        // Withdraw the eligible balanace as a delayed withdrawal.
        if (activeValidatorCount == 0) {
            _sendETH_AsDelayedWithdrawal(podOwner, eligibleBalance);

            // emit event
        } else {
            // Otherwise, create a new partial withdrawal checkpoint, overwriting
            // a previous block's checkpoint if it exists.
            uint64 oracleTimestamp = uint64(block.timestamp);
            require(currentCheckpointTimestamp != oracleTimestamp, "checkpoint already created this block");
            
            currentCheckpointTimestamp = oracleTimestamp;
            currentCheckpoint = Checkpoint({
                proofsRemaining: uint24(activeValidatorCount),
                eligibleBalance: uint232(eligibleBalance)
            });

            // emit event
        }
    }

    /**
     * @notice This function processes a proof for one or more validators' balances.
     *         TODO - more comments
     * @param oracleTimestamp The oracleTimestamp whose state root the proof will be proven against.
     * @param validatorIndices is the list of indices of the validators being proven, refer to consensus specs 
     * @param stateRootProof proves a `beaconStateRoot` against a block root fetched from the oracle
     * @param validatorFieldsProofs proofs against the `beaconStateRoot` for each validator in `validatorFields`
     * @param validatorFields are the fields of the "Validator Container", refer to consensus specs
     * @dev For more details on the Beacon Chain spec, see: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#validator
     */
    function verifyBalanceUpdates(
        uint64 oracleTimestamp,
        uint40[] calldata validatorIndices,
        BeaconChainProofs.StateRootProof calldata stateRootProof,
        bytes[] calldata validatorFieldsProofs,
        bytes32[][] calldata validatorFields
    ) external onlyWhenNotPaused(PAUSED_EIGENPODS_VERIFY_BALANCE_UPDATE) {
        require(
            (validatorIndices.length == validatorFieldsProofs.length) && (validatorFieldsProofs.length == validatorFields.length),
            "EigenPod.verifyBalanceUpdates: validatorIndices and proofs must be same length"
        );

        /// TODO: I got rid of this check, because proving against an old checkpoint requires
        /// "stale" proofs. What we COULD do is prevent a share delta if the timestamp is
        /// too stale. 
        // require(
        //     oracleTimestamp + VERIFY_BALANCE_UPDATE_WINDOW_SECONDS >= block.timestamp,
        //     "EigenPod.verifyBalanceUpdates: specified timestamp is too far in past"
        // );

        // Check for a partial withdrawal checkpoint using this oracle timestamp
        (bool activeCheckpoint, Checkpoint memory checkpoint) = _getCheckpoint(oracleTimestamp);

        // Get the cached beacon state root for this timestamp, or validate `stateRootProof`
        bytes32 beaconStateRoot = _getOrValidateStateRoot(oracleTimestamp, stateRootProof);

        // Process each validator balance proof, keeping track of the total share delta
        int256 sharesDeltaGwei;
        for (uint256 i = 0; i < validatorIndices.length; i++) {
            bytes32 pubkeyHash = validatorFields[i].getPubkeyHash();

            sharesDeltaGwei += _verifyBalanceUpdate(
                oracleTimestamp,
                pubkeyHash,
                validatorIndices[i],
                stateRootProof.beaconStateRoot,
                validatorFieldsProofs[i], // Use validator fields proof because contains the effective balance
                validatorFields[i]
            );

            // If we're working on a partial withdrawal checkpoint and we haven't seen
            // this validator yet, mark the validator as proven
            if (activeCheckpoint && !validatorProven[oracleTimestamp][pubkeyHash]) {
                validatorProven[oracleTimestamp][pubkeyHash] = true;
                checkpoint.proofsRemaining--;
            }
        }

        // If we have updated validator balances, send them to the EigenPodManager
        if (sharesDeltaGwei != 0) {
            eigenPodManager.recordBeaconChainETHBalanceUpdate(podOwner, sharesDeltaGwei * int256(GWEI_TO_WEI));
        }

        // If this oracle timestamp concerns a partial withdrawal checkpoint, update the stored checkpoint
        if (activeCheckpoint) {
            // If we've proven the pod's entire validator set, we're done with this checkpoint.
            // Delete the current checkpoint and withdraw the eligible balance.
            if (checkpoint.proofsRemaining == 0) {
                delete currentCheckpoint;
                delete currentCheckpointTimestamp;

                _sendETH_AsDelayedWithdrawal(podOwner, checkpoint.eligibleBalance);
            } else {
                currentCheckpoint = checkpoint;
            }
        }
    }

    /**
     * @notice This function records full withdrawals on behalf of one or more of this EigenPod's validators
     * @param oracleTimestamp is the timestamp of the oracle slot that the withdrawal is being proven against
     * @param stateRootProof proves a `beaconStateRoot` against a block root fetched from the oracle
     * @param withdrawalProofs proves several withdrawal-related values against the `beaconStateRoot`
     * @param validatorFieldsProofs proves `validatorFields` against the `beaconStateRoot`
     * @param withdrawalFields are the fields of the withdrawals being proven
     * @param validatorFields are the fields of the validators being proven
     */
    function verifyAndProcessWithdrawals(
        uint64 oracleTimestamp,
        BeaconChainProofs.StateRootProof calldata stateRootProof,
        BeaconChainProofs.WithdrawalProof[] calldata withdrawalProofs,
        bytes[] calldata validatorFieldsProofs,
        bytes32[][] calldata validatorFields,
        bytes32[][] calldata withdrawalFields
    ) external onlyWhenNotPaused(PAUSED_EIGENPODS_VERIFY_WITHDRAWAL) {
        require(
            (validatorFields.length == validatorFieldsProofs.length) &&
                (validatorFieldsProofs.length == withdrawalProofs.length) &&
                (withdrawalProofs.length == withdrawalFields.length),
            "EigenPod.verifyAndProcessWithdrawals: inputs must be same length"
        );

        // Check for a partial withdrawal checkpoint using this oracle timestamp
        (bool activeCheckpoint, Checkpoint memory checkpoint) = _getCheckpoint(oracleTimestamp);

        // Get the cached beacon state root for this timestamp, or validate `stateRootProof`
        bytes32 beaconStateRoot = _getOrValidateStateRoot(oracleTimestamp, stateRootProof);

        VerifiedWithdrawal memory withdrawalSummary;
        for (uint256 i = 0; i < withdrawalFields.length; i++) {
            VerifiedWithdrawal memory verifiedWithdrawal = _verifyAndProcessWithdrawal(
                beaconStateRoot,
                withdrawalProofs[i],
                validatorFieldsProofs[i],
                validatorFields[i],
                withdrawalFields[i]
            );

            withdrawalSummary.amountToQueueGwei += verifiedWithdrawal.amountToQueueGwei;
            withdrawalSummary.sharesDeltaGwei += verifiedWithdrawal.sharesDeltaGwei;

            // If we're working on a partial withdrawal checkpoint and we haven't seen
            // this validator yet, mark the validator as proven
            if (activeCheckpoint && !validatorProven[oracleTimestamp][pubkeyHash]) {
                validatorProven[oracleTimestamp][pubkeyHash] = true;
                checkpoint.proofsRemaining--;
            }
        }

        // If any withdrawals resulted in a change in the pod's shares, update the EigenPodManager
        if (withdrawalSummary.sharesDeltaGwei != 0) {
            eigenPodManager.recordBeaconChainETHBalanceUpdate(podOwner, withdrawalSummary.sharesDeltaGwei * int256(GWEI_TO_WEI));
        }

        // If this oracle timestamp concerns a partial withdrawal checkpoint, update the stored checkpoint
        if (activeCheckpoint) {
            // Remove any full withdrawals from the checkpoint's eligible balance
            checkpoint.eligibleBalance -= (withdrawalSummary.amountToQueueGwei * GWEI_TO_WEI);

            // If we've proven the pod's entire validator set, we're done with this checkpoint.
            // Delete the current checkpoint and withdraw the eligible balance.
            if (checkpoint.proofsRemaining == 0) {
                delete currentCheckpoint;
                delete currentCheckpointTimestamp;
                
                _sendETH_AsDelayedWithdrawal(podOwner, checkpoint.eligibleBalance);
            } else {
                currentCheckpoint = checkpoint;
            }
        }
    }

    /*******************************************************************************
                    EXTERNAL FUNCTIONS CALLABLE BY EIGENPOD OWNER
    *******************************************************************************/

    /**
     * @notice This function verifies that the withdrawal credentials of validator(s) owned by the podOwner are pointed to
     * this contract. It also verifies the effective balance  of the validator.  It verifies the provided proof of the ETH validator against the beacon chain state
     * root, marks the validator as 'active' in EigenLayer, and credits the restaked ETH in Eigenlayer.
     * @param oracleTimestamp is the Beacon Chain timestamp whose state root the `proof` will be proven against.
     * @param stateRootProof proves a `beaconStateRoot` against a block root fetched from the oracle
     * @param validatorIndices is the list of indices of the validators being proven, refer to consensus specs
     * @param validatorFieldsProofs proofs against the `beaconStateRoot` for each validator in `validatorFields`
     * @param validatorFields are the fields of the "Validator Container", refer to consensus specs
     * for details: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#validator
     */
    function verifyWithdrawalCredentials(
        uint64 oracleTimestamp,
        BeaconChainProofs.StateRootProof calldata stateRootProof,
        uint40[] calldata validatorIndices,
        bytes[] calldata validatorFieldsProofs,
        bytes32[][] calldata validatorFields
    )
        external
        onlyEigenPodOwner
        onlyWhenNotPaused(PAUSED_EIGENPODS_VERIFY_CREDENTIALS)
        // check that the provided `oracleTimestamp` is after the `mostRecentWithdrawalTimestamp`
        proofIsForValidTimestamp(oracleTimestamp)
        // ensure that caller has previously enabled restaking by calling `activateRestaking()`
        hasEnabledRestaking
    {
        require(
            (validatorIndices.length == validatorFieldsProofs.length) &&
                (validatorFieldsProofs.length == validatorFields.length),
            "EigenPod.verifyWithdrawalCredentials: validatorIndices and proofs must be same length"
        );

        /**
         * Withdrawal credential proof should not be "stale" (older than VERIFY_BALANCE_UPDATE_WINDOW_SECONDS) as we are doing a balance check here
         * The validator container persists as the state evolves and even after the validator exits. So we can use a more "fresh" credential proof within
         * the VERIFY_BALANCE_UPDATE_WINDOW_SECONDS window, not just the first proof where the validator container is registered in the state.
         */
        require(
            oracleTimestamp + VERIFY_BALANCE_UPDATE_WINDOW_SECONDS >= block.timestamp,
            "EigenPod.verifyWithdrawalCredentials: specified timestamp is too far in past"
        );

        // Get the cached beacon state root for this timestamp, or validate `stateRootProof`
        bytes32 beaconStateRoot = _getOrValidateStateRoot(oracleTimestamp, stateRootProof);

        uint256 totalAmountToBeRestakedWei;
        for (uint256 i = 0; i < validatorIndices.length; i++) {
            totalAmountToBeRestakedWei += _verifyWithdrawalCredentials(
                oracleTimestamp,
                beaconStateRoot,
                validatorIndices[i],
                validatorFieldsProofs[i],
                validatorFields[i]
            );
        }

        // Update the EigenPodManager on this pod's new balance
        eigenPodManager.recordBeaconChainETHBalanceUpdate(podOwner, int256(totalAmountToBeRestakedWei));
    }

    /// @notice Called by the pod owner to withdraw the nonBeaconChainETHBalanceWei
    function withdrawNonBeaconChainETHBalanceWei(
        address recipient,
        uint256 amountToWithdraw
    ) external onlyEigenPodOwner onlyWhenNotPaused(PAUSED_NON_PROOF_WITHDRAWALS) {
        require(
            amountToWithdraw <= nonBeaconChainETHBalanceWei,
            "EigenPod.withdrawnonBeaconChainETHBalanceWei: amountToWithdraw is greater than nonBeaconChainETHBalanceWei"
        );
        nonBeaconChainETHBalanceWei -= amountToWithdraw;
        emit NonBeaconChainETHWithdrawn(recipient, amountToWithdraw);
        _sendETH_AsDelayedWithdrawal(recipient, amountToWithdraw);
    }

    /// @notice called by owner of a pod to remove any ERC20s deposited in the pod
    function recoverTokens(
        IERC20[] memory tokenList,
        uint256[] memory amountsToWithdraw,
        address recipient
    ) external onlyEigenPodOwner onlyWhenNotPaused(PAUSED_NON_PROOF_WITHDRAWALS) {
        require(
            tokenList.length == amountsToWithdraw.length,
            "EigenPod.recoverTokens: tokenList and amountsToWithdraw must be same length"
        );
        for (uint256 i = 0; i < tokenList.length; i++) {
            tokenList[i].safeTransfer(recipient, amountsToWithdraw[i]);
        }
    }

    /**
     * @notice Called by the pod owner to activate restaking by withdrawing
     * all existing ETH from the pod and preventing further withdrawals via
     * "withdrawBeforeRestaking()"
     */
    function activateRestaking()
        external
        onlyWhenNotPaused(PAUSED_EIGENPODS_VERIFY_CREDENTIALS)
        onlyEigenPodOwner
        hasNeverRestaked
    {
        hasRestaked = true;
        _processWithdrawalBeforeRestaking(podOwner);

        emit RestakingActivated(podOwner);
    }

    /// @notice Called by the pod owner to withdraw the balance of the pod when `hasRestaked` is set to false
    function withdrawBeforeRestaking() external onlyEigenPodOwner hasNeverRestaked {
        _processWithdrawalBeforeRestaking(podOwner);
    }

    /*******************************************************************************
                    EXTERNAL FUNCTIONS CALLABLE BY EIGENPODMANAGER
    *******************************************************************************/

    /// @notice Called by EigenPodManager when the owner wants to create another ETH validator.
    function stake(
        bytes calldata pubkey,
        bytes calldata signature,
        bytes32 depositDataRoot
    ) external payable onlyEigenPodManager {
        // stake on ethpos
        require(msg.value == 32 ether, "EigenPod.stake: must initially stake for any validator with 32 ether");
        ethPOS.deposit{value: 32 ether}(pubkey, _podWithdrawalCredentials(), signature, depositDataRoot);
        emit EigenPodStaked(pubkey);
    }

    /**
     * @notice Transfers `amountWei` in ether from this contract to the specified `recipient` address
     * @notice Called by EigenPodManager to withdrawBeaconChainETH that has been added to the EigenPod's balance due to a withdrawal from the beacon chain.
     * @dev The podOwner must have already proved sufficient withdrawals, so that this pod's `withdrawableRestakedExecutionLayerGwei` exceeds the
     * `amountWei` input (when converted to GWEI).
     * @dev Reverts if `amountWei` is not a whole Gwei amount
     */
    function withdrawRestakedBeaconChainETH(address recipient, uint256 amountWei) external onlyEigenPodManager {
        require(amountWei % GWEI_TO_WEI == 0, "EigenPod.withdrawRestakedBeaconChainETH: amountWei must be a whole Gwei amount");
        uint64 amountGwei = uint64(amountWei / GWEI_TO_WEI);
        require(amountGwei <= withdrawableRestakedExecutionLayerGwei, "EigenPod.withdrawRestakedBeaconChainETH: amountGwei exceeds withdrawableRestakedExecutionLayerGwei");
        withdrawableRestakedExecutionLayerGwei -= amountGwei;
        emit RestakedBeaconChainETHWithdrawn(recipient, amountWei);
        // transfer ETH from pod to `recipient` directly
        _sendETH(recipient, amountWei);
    }

    /*******************************************************************************
                                INTERNAL FUNCTIONS
    *******************************************************************************/
    /**
     * @notice internal function that proves an individual validator's withdrawal credentials
     * @param oracleTimestamp is the timestamp whose state root the `proof` will be proven against.
     * @param validatorIndex is the index of the validator being proven
     * @param validatorFieldsProof is the bytes that prove the ETH validator's  withdrawal credentials against a beacon chain state root
     * @param validatorFields are the fields of the "Validator Container", refer to consensus specs
     */
    function _verifyWithdrawalCredentials(
        uint64 oracleTimestamp,
        bytes32 beaconStateRoot,
        uint40 validatorIndex,
        bytes calldata validatorFieldsProof,
        bytes32[] calldata validatorFields
    ) internal returns (uint256) {
        bytes32 validatorPubkeyHash = validatorFields.getPubkeyHash();
        ValidatorInfo memory validatorInfo = _validatorPubkeyHashToInfo[validatorPubkeyHash];

        // Withdrawal credential proofs should only be processed for "INACTIVE" validators
        require(
            validatorInfo.status == VALIDATOR_STATUS.INACTIVE,
            "EigenPod.verifyCorrectWithdrawalCredentials: Validator must be inactive to prove withdrawal credentials"
        );

        // Ensure the `validatorFields` we're proving have the correct withdrawal credentials
        require(
            validatorFields.getWithdrawalCredentials() == bytes32(_podWithdrawalCredentials()),
            "EigenPod.verifyCorrectWithdrawalCredentials: Proof is not for this EigenPod"
        );

        /**
         * Deserialize the balance field from the Validator struct.  Note that this is the "effective" balance of the validator
         * rather than the current balance.  Effective balance is generated via a hystersis function such that an effective
         * balance, always a multiple of 1 ETH, will only lower to the next multiple of 1 ETH if the current balance is less
         * than 0.25 ETH below their current effective balance.  For example, if the effective balance is 31ETH, it only falls to
         * 30ETH when the true balance falls below 30.75ETH.  Thus in the worst case, the effective balance is overestimating the
         * actual validator balance by 0.25 ETH. 
         */
        uint64 validatorEffectiveBalanceGwei = validatorFields.getEffectiveBalanceGwei();

        // Verify passed-in validatorFields against verified beaconStateRoot:
        BeaconChainProofs.verifyValidatorFields({
            beaconStateRoot: beaconStateRoot,
            validatorFields: validatorFields,
            validatorFieldsProof: validatorFieldsProof,
            validatorIndex: validatorIndex
        });

        // Proofs complete - update this validator's status, record its proven balance, and save in state:
        activeValidatorCount++;
        validatorInfo.status = VALIDATOR_STATUS.ACTIVE;
        validatorInfo.validatorIndex = validatorIndex;
        validatorInfo.mostRecentBalanceUpdateTimestamp = oracleTimestamp;

        if (validatorEffectiveBalanceGwei > MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR) {
            validatorInfo.restakedBalanceGwei = MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR;
        } else {
            validatorInfo.restakedBalanceGwei = validatorEffectiveBalanceGwei;
        }
        _validatorPubkeyHashToInfo[validatorPubkeyHash] = validatorInfo;

        // Record this validator as proven so it can't be used within an existing partial
        // withdrawal checkpoint
        validatorProven[oracleTimestamp][validatorPubkeyHash] = true;

        emit ValidatorRestaked(validatorIndex);
        emit ValidatorBalanceUpdated(validatorIndex, oracleTimestamp, validatorInfo.restakedBalanceGwei);

        return validatorInfo.restakedBalanceGwei * GWEI_TO_WEI;
    }

    function _verifyBalanceUpdate(
        uint64 oracleTimestamp,
        bytes32 validatorPubkeyHash,
        uint40 validatorIndex,
        bytes32 beaconStateRoot,
        bytes calldata validatorFieldsProof,
        bytes32[] calldata validatorFields
    ) internal returns(int256 sharesDeltaGwei){
        uint64 validatorEffectiveBalanceGwei = validatorFields.getEffectiveBalanceGwei();
        ValidatorInfo memory validatorInfo = _validatorPubkeyHashToInfo[validatorPubkeyHash];   

        // 1. Balance updates should only be performed on "ACTIVE" validators
        require(
            validatorInfo.status == VALIDATOR_STATUS.ACTIVE, 
            "EigenPod.verifyBalanceUpdate: Validator not active"
        );

        // 2. Balance updates should only be made before a validator is fully withdrawn. 
        // -- A withdrawable validator may not have withdrawn yet, so we require their balance is nonzero
        // -- A fully withdrawn validator should withdraw via verifyAndProcessWithdrawals
        if (validatorFields.getWithdrawableEpoch() <= _timestampToEpoch(oracleTimestamp)) {
            require(
                validatorEffectiveBalanceGwei > 0,
                "EigenPod.verifyBalanceUpdate: validator is withdrawable but has not withdrawn"
            );
        }

        // Verify passed-in validatorFields against verified beaconStateRoot:
        BeaconChainProofs.verifyValidatorFields({
            beaconStateRoot: beaconStateRoot,
            validatorFields: validatorFields,
            validatorFieldsProof: validatorFieldsProof,
            validatorIndex: validatorIndex
        });

        // If we're processing an older balance proof, we don't need to record any balance/share changes
        if (oracleTimestamp < validatorInfo.mostRecentBalanceUpdateTimestamp) {
            return;
        }

        // If this is the most recent proof we've seen, calculate a share delta
        // to be sent to the EigenPodManager
        uint64 currentRestakedBalanceGwei = validatorInfo.restakedBalanceGwei;
        uint64 newRestakedBalanceGwei;
        if (validatorEffectiveBalanceGwei > MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR) {
            newRestakedBalanceGwei = MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR;
        } else {
            newRestakedBalanceGwei = validatorEffectiveBalanceGwei;
        }
        
        // Update validator balance and timestamp, and save to state:
        validatorInfo.restakedBalanceGwei = newRestakedBalanceGwei;
        validatorInfo.mostRecentBalanceUpdateTimestamp = oracleTimestamp;
        _validatorPubkeyHashToInfo[validatorPubkeyHash] = validatorInfo;

        // If our new and old balances differ, calculate the delta and send to the EigenPodManager
        if (newRestakedBalanceGwei != currentRestakedBalanceGwei) {
            emit ValidatorBalanceUpdated(validatorIndex, oracleTimestamp, newRestakedBalanceGwei);

            sharesDeltaGwei = _calculateSharesDelta({
                newAmountGwei: newRestakedBalanceGwei,
                previousAmountGwei: currentRestakedBalanceGwei
            });
        }
    }

    function _verifyAndProcessWithdrawal(
        bytes32 beaconStateRoot,
        BeaconChainProofs.WithdrawalProof calldata withdrawalProof,
        bytes calldata validatorFieldsProof,
        bytes32[] calldata validatorFields,
        bytes32[] calldata withdrawalFields
    )
        internal
        /**
         * Check that the provided timestamp being proven against is after the `mostRecentWithdrawalTimestamp`.
         * Without this check, there is an edge case where a user proves a past withdrawal for a validator whose funds they already withdrew,
         * as a way to "withdraw the same funds twice" without providing adequate proof.
         * Note that this check is not made using the oracleTimestamp as in the `verifyWithdrawalCredentials` proof; instead this proof
         * proof is made for the timestamp of the withdrawal, which may be within SLOTS_PER_HISTORICAL_ROOT slots of the oracleTimestamp.
         * This difference in modifier usage is OK, since it is still not possible to `verifyAndProcessWithdrawal` against a slot that occurred
         * *prior* to the proof provided in the `verifyWithdrawalCredentials` function.
         */
        proofIsForValidTimestamp(withdrawalProof.getWithdrawalTimestamp())
        returns (VerifiedWithdrawal memory)
    {
        uint64 withdrawalTimestamp = withdrawalProof.getWithdrawalTimestamp();
        bytes32 validatorPubkeyHash = validatorFields.getPubkeyHash();

        /**
         * Withdrawal processing should only be performed for "ACTIVE" or "WITHDRAWN" validators.
         * (WITHDRAWN is allowed because technically you can deposit to a validator even after it exits)
         */
        require(
            _validatorPubkeyHashToInfo[validatorPubkeyHash].status == VALIDATOR_STATUS.ACTIVE,
            "EigenPod._verifyAndProcessWithdrawal: Validator never proven to have withdrawal credentials pointed to this contract"
        );

        // Ensure we don't process the same withdrawal twice
        require(
            !provenWithdrawal[validatorPubkeyHash][withdrawalTimestamp],
            "EigenPod._verifyAndProcessWithdrawal: withdrawal has already been proven for this timestamp"
        );

        require(
            withdrawalProof.getWithdrawalEpoch() >= validatorFields.getWithdrawableEpoch(),
            "Must prove full withdrawal"
        );

        provenWithdrawal[validatorPubkeyHash][withdrawalTimestamp] = true;

        // Verifying the withdrawal against verified beaconStateRoot:
        BeaconChainProofs.verifyWithdrawal({
            beaconStateRoot: beaconStateRoot, 
            withdrawalFields: withdrawalFields, 
            withdrawalProof: withdrawalProof,
            denebForkTimestamp: eigenPodManager.denebForkTimestamp()
        });

        uint40 validatorIndex = withdrawalFields.getValidatorIndex();

        // Verify passed-in validatorFields against verified beaconStateRoot:
        BeaconChainProofs.verifyValidatorFields({
            beaconStateRoot: beaconStateRoot,
            validatorFields: validatorFields,
            validatorFieldsProof: validatorFieldsProof,
            validatorIndex: validatorIndex
        });

        uint64 withdrawalAmountGwei = withdrawalFields.getWithdrawalAmountGwei();
        
        /**
         * First, determine withdrawal amounts. We need to know:
         * 1. How much can be withdrawn immediately
         * 2. How much needs to be withdrawn via the EigenLayer withdrawal queue
         */

        uint64 amountToQueueGwei;

        if (withdrawalAmountGwei > MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR) {
            amountToQueueGwei = MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR;
        } else {
            amountToQueueGwei = withdrawalAmountGwei;
        }
 
        /**
         * If the withdrawal is for more than the max per-validator balance, we mark 
         * the max as "withdrawable" via the queue, and withdraw the excess immediately
         */
 
        VerifiedWithdrawal memory verifiedWithdrawal;
        verifiedWithdrawal.amountToQueueGwei = amountToQueueGwei;
        withdrawableRestakedExecutionLayerGwei += amountToQueueGwei;
         
        /**
         * Next, calculate the change in number of shares this validator is "backing":
         * - Anything that needs to go through the withdrawal queue IS backed
         * - Anything immediately withdrawn IS NOT backed
         *
         * This means that this validator is currently backing `amountToQueueGwei` shares.
         */
 
        verifiedWithdrawal.sharesDeltaGwei = _calculateSharesDelta({
            newAmountGwei: amountToQueueGwei,
            previousAmountGwei: validatorInfo.restakedBalanceGwei
        });
 
        /**
         * Finally, the validator is fully withdrawn. Update their status and place in state:
         */
 
        validatorInfo.restakedBalanceGwei = 0;
        validatorInfo.status = VALIDATOR_STATUS.WITHDRAWN;
        activeValidatorCount--;
 
        _validatorPubkeyHashToInfo[validatorPubkeyHash] = validatorInfo;
 
        emit FullWithdrawalRedeemed(validatorIndex, withdrawalTimestamp, recipient, withdrawalAmountGwei);
 
        return verifiedWithdrawal;
    }

    /// @dev Checks if we have an active partial withdrawal checkpoint for the given `oracleTimestamp`
    ///      If we do, returns true and loads the checkpoint from state.
    function _getCheckpoint(uint64 oracleTimestamp) internal view returns (bool, Checkpoint memory) {
        if (oracleTimestamp != 0 && oracleTimestamp == currentCheckpointTimestamp) {
            return (true, currentCheckpoint);
        }
    }

    /// @dev Checks if we have a cached beaconStateRoot proven for this `oracleTimestamp`.
    ///     If we don't, this validates the `stateRootProof` against the oracle block root,
    ///     and caches the valid beaconStateRoot.
    function _getOrValidateStateRoot(
        uint64 oracleTimestamp, 
        BeaconChainProofs.StateRootProof calldata stateRootProof
    ) internal view returns (bytes32) {
        bytes32 beaconStateRoot = cachedStateRoots[oracleTimestamp];

        // If we don't already have a cached beacon state root at this timestamp,
        // get the block root for the oracleTimestamp and verify the StateRootProof
        if (beaconStateRoot == bytes32(0)) {
            BeaconChainProofs.verifyStateRootAgainstLatestBlockRoot({
                latestBlockRoot: eigenPodManager.getBlockRootAtTimestamp(oracleTimestamp),
                beaconStateRoot: stateRootProof.beaconStateRoot,
                stateRootProof: stateRootProof.proof
            });

            // Cache the validated beaconStateRoot
            beaconStateRoot = stateRootProof.beaconStateRoot;
            cachedStateRoots[oracleTimestamp] = beaconStateRoot;
        }

        return beaconStateRoot;
    }

    function _processWithdrawalBeforeRestaking(address _podOwner) internal {
        mostRecentWithdrawalTimestamp = uint32(block.timestamp);
        nonBeaconChainETHBalanceWei = 0;
        _sendETH_AsDelayedWithdrawal(_podOwner, address(this).balance);
    }

    function _sendETH(address recipient, uint256 amountWei) internal {
        Address.sendValue(payable(recipient), amountWei);
    }

    function _sendETH_AsDelayedWithdrawal(address recipient, uint256 amountWei) internal {
        delayedWithdrawalRouter.createDelayedWithdrawal{value: amountWei}(podOwner, recipient);
    }

    function _podWithdrawalCredentials() internal view returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(this));
    }

    ///@notice Calculates the pubkey hash of a validator's pubkey as per SSZ spec
    function _calculateValidatorPubkeyHash(bytes memory validatorPubkey) internal pure returns (bytes32){
        require(validatorPubkey.length == 48, "EigenPod._calculateValidatorPubkeyHash must be a 48-byte BLS public key");
        return sha256(abi.encodePacked(validatorPubkey, bytes16(0)));
    }

    /**
     * Calculates delta between two share amounts and returns as an int256
     */
    function _calculateSharesDelta(uint64 newAmountGwei, uint64 previousAmountGwei) internal pure returns (int256) {
        return
            int256(uint256(newAmountGwei)) - int256(uint256(previousAmountGwei));
    }

    /**
     * @dev Converts a timestamp to a beacon chain epoch by calculating the number of
     * seconds since genesis, and dividing by seconds per epoch.
     * reference: https://github.com/ethereum/consensus-specs/blob/ce240ca795e257fc83059c4adfd591328c7a7f21/specs/bellatrix/beacon-chain.md#compute_timestamp_at_slot
     */
    function _timestampToEpoch(uint64 timestamp) internal view returns (uint64) {
        require(timestamp >= GENESIS_TIME, "EigenPod._timestampToEpoch: timestamp is before genesis");
        return (timestamp - GENESIS_TIME) / BeaconChainProofs.SECONDS_PER_EPOCH;
    }

    /*******************************************************************************
                            VIEW FUNCTIONS
    *******************************************************************************/

    function validatorPubkeyHashToInfo(bytes32 validatorPubkeyHash) external view returns (ValidatorInfo memory) {
        return _validatorPubkeyHashToInfo[validatorPubkeyHash];
    }

    /// @notice Returns the validatorInfo for a given validatorPubkey
    function validatorPubkeyToInfo(bytes calldata validatorPubkey) external view returns (ValidatorInfo memory) {
        return _validatorPubkeyHashToInfo[_calculateValidatorPubkeyHash(validatorPubkey)];
    }

    function validatorStatus(bytes32 pubkeyHash) external view returns (VALIDATOR_STATUS) {
        return _validatorPubkeyHashToInfo[pubkeyHash].status;
    }

        /// @notice Returns the validator status for a given validatorPubkey
    function validatorStatus(bytes calldata validatorPubkey) external view returns (VALIDATOR_STATUS) {
        bytes32 validatorPubkeyHash = _calculateValidatorPubkeyHash(validatorPubkey);
        return _validatorPubkeyHashToInfo[validatorPubkeyHash].status;
    }


    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[44] private __gap;
}
