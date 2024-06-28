// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "./StrategyBase.sol";
import "../permissions/Pausable.sol";

/**
 * @title Factory contract for deploying StrategyBase contracts for arbitrary ERC20 tokens
 *        and automatically adding them to the StrategyWhitelist in EigenLayer.
 * @author Layr Labs, Inc.
 * @dev This may not be compatible with non-standard ERC20 tokens. Caution is warranted.
 */
contract StrategyFactory is OwnableUpgradeable, Pausable {

    uint8 internal constant PAUSED_NEW_STRATEGIES = 0;

    /// @notice EigenLayer's StrategyManager contract
    IStrategyManager public immutable strategyManager;

    StrategyBase public strategyImplementation;

    ProxyAdmin public eigenLayerProxyAdmin;

    // @notice Mapping token => strategy contract for the token
    mapping(IERC20 => IStrategy) public tokenStrategies;

    event StrategyImplementationModified(StrategyBase previousImplementation, StrategyBase newImplementation);
    event ProxyAdminModified(ProxyAdmin previousProxyAdmin, ProxyAdmin newProxyAdmin);
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
        StrategyBase _strategyImplementation,
        ProxyAdmin _eigenLayerProxyAdmin
    )
        public virtual initializer
    {
        _transferOwnership(_initialOwner);
        _initializePauser(_pauserRegistry, _initialPausedStatus);
        _setStrategyImplementation(_strategyImplementation);
        _setProxyAdmin(_eigenLayerProxyAdmin);
    }

    /**
     * @notice Deploy a new StrategyBase contract for the ERC20 token.
     * @dev A strategy contract must not yet exist for the token.
     * $dev Immense caution is warranted for non-standard ERC20 tokens, particularly "reentrant" tokens
     * like those that conform to ERC777.
     */
    function deployNewStrategy(IERC20 token) external onlyWhenNotPaused(PAUSED_NEW_STRATEGIES) returns (IStrategy newStrategy) {
        require(tokenStrategies[token] == IStrategy(address(0)),
            "StrategyFactory.deployNewStrategy: Strategy already exists for token");
        IStrategy strategy = IStrategy(
            address(
                new TransparentUpgradeableProxy(
                    address(strategyImplementation),
                    address(eigenLayerProxyAdmin),
                    abi.encodeWithSelector(StrategyBase.initialize.selector, token, pauserRegistry)
                )
            )
        );
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

    // @notice Owner-only function to modify the `eigenLayerProxyAdmin`
    function setProxyAdmin(ProxyAdmin _eigenLayerProxyAdmin) external onlyOwner {
        _setProxyAdmin(_eigenLayerProxyAdmin);
    }

    // @notice Owner-only function to modify the `strategyImplementation`
    function setStrategyImplementation(StrategyBase _strategyImplementation) external onlyOwner {
        _setStrategyImplementation(_strategyImplementation);
    }

    function _setStrategyForToken(IERC20 token, IStrategy strategy) internal {
        tokenStrategies[token] = strategy;
        emit StrategySetForToken(token, strategy);
    }

    function _setProxyAdmin(ProxyAdmin _eigenLayerProxyAdmin) internal {
        emit ProxyAdminModified(eigenLayerProxyAdmin, _eigenLayerProxyAdmin);
        eigenLayerProxyAdmin = _eigenLayerProxyAdmin;
    }

    function _setStrategyImplementation(StrategyBase _strategyImplementation) internal {
        emit StrategyImplementationModified(strategyImplementation, _strategyImplementation);
        strategyImplementation = _strategyImplementation;
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[47] private __gap;
}
