// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "./StrategyBase.sol";
import "../permissions/Pausable.sol";

/**
 * @title Factory contract for deploying BeaconProxies of a Strategy contract implementation for arbitrary ERC20 tokens
 *        and automatically adding them to the StrategyWhitelist in EigenLayer.
 * @author Layr Labs, Inc.
 * @dev This may not be compatible with non-standard ERC20 tokens. Caution is warranted.
 */
contract StrategyFactory is OwnableUpgradeable, Pausable {

    uint8 internal constant PAUSED_NEW_STRATEGIES = 0;

    /// @notice EigenLayer's StrategyManager contract
    IStrategyManager public immutable strategyManager;

    IBeacon public strategyBeacon;

    // @notice Mapping token => strategy contract for the token
    mapping(IERC20 => IStrategy) public tokenStrategies;

    event StrategyBeaconModified(IBeacon previousImplementation, IBeacon newImplementation);
    event StrategySetForToken(IERC20 token, IStrategy strategy);

    /// @notice Since this contract is designed to be initializable, the constructor simply sets the immutable variables.
    constructor(IStrategyManager _strategyManager) {
        strategyManager = _strategyManager;
        _disableInitializers();
    }

    function initialize(
        address _initialOwner,
        IPauserRegistry _pauserRegistry,
        uint256 _initialPausedStatus,
        IBeacon _strategyBeacon
    )
        public virtual initializer
    {
        _transferOwnership(_initialOwner);
        _initializePauser(_pauserRegistry, _initialPausedStatus);
        _setStrategyBeacon(_strategyBeacon);
    }

    /**
     * @notice Deploy a new strategyBeacon contract for the ERC20 token.
     * @dev A strategy contract must not yet exist for the token.
     * $dev Immense caution is warranted for non-standard ERC20 tokens, particularly "reentrant" tokens
     * like those that conform to ERC777.
     */
    function deployNewStrategy(IERC20 token) external onlyWhenNotPaused(PAUSED_NEW_STRATEGIES) returns (IStrategy newStrategy) {
        require(tokenStrategies[token] == IStrategy(address(0)),
            "StrategyFactory.deployNewStrategy: Strategy already exists for token");
        IStrategy strategy = IStrategy(address(
            new BeaconProxy(
                address(strategyBeacon),
                abi.encodeWithSelector(StrategyBase.initialize.selector, token, pauserRegistry)
            )
        ));
        _setStrategyForToken(token, strategy);
        IStrategy[] memory strategiesToWhitelist = new IStrategy[](1);
        bool[] memory thirdPartyTransfersForbiddenValues = new bool[](1);
        strategiesToWhitelist[0] = strategy;
        thirdPartyTransfersForbiddenValues[0] = false;
        strategyManager.addStrategiesToDepositWhitelist(strategiesToWhitelist, thirdPartyTransfersForbiddenValues);
        return strategy;
    }

    /** 
     * @notice Owner-only function to pass through a call to `StrategyManager.addStrategiesToDepositWhitelist`
     * @dev Also adds the `strategiesToWhitelist` to the `tokenStrategies` mapping
     */
    function whitelistStrategies(
        IStrategy[] calldata strategiesToWhitelist,
        bool[] calldata thirdPartyTransfersForbiddenValues
    ) external onlyOwner {
        strategyManager.addStrategiesToDepositWhitelist(strategiesToWhitelist, thirdPartyTransfersForbiddenValues);
        for (uint256 i = 0; i < strategiesToWhitelist.length; ++i) {
            IERC20 underlyingToken = strategiesToWhitelist[i].underlyingToken();
            _setStrategyForToken(underlyingToken, strategiesToWhitelist[i]);
        }
    }

    // @notice Owner-only function to add (existing) Strategy contracts to the `tokenStrategies` mapping
    function editTokenStrategiesMapping(
        IERC20[] calldata tokens,
        IStrategy[] calldata strategies
    ) external onlyOwner {
        require(tokens.length == strategies.length,
            "StrategyFactory.editTokenStrategiesMapping: input length mismatch");
        for (uint256 i = 0; i < tokens.length; ++i) {
            _setStrategyForToken(tokens[i], strategies[i]);
        }
    }

    // @notice Owner-only function to modify the `strategyBeacon`
    function setStrategyBeacon(IBeacon _strategyBeacon) external onlyOwner {
        _setStrategyBeacon(_strategyBeacon);
    }

    function _setStrategyForToken(IERC20 token, IStrategy strategy) internal {
        tokenStrategies[token] = strategy;
        emit StrategySetForToken(token, strategy);
    }

    function _setStrategyBeacon(IBeacon _strategyBeacon) internal {
        emit StrategyBeaconModified(strategyBeacon, _strategyBeacon);
        strategyBeacon = _strategyBeacon;
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[47] private __gap;
}
