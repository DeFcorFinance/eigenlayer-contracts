// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";

import "src/contracts/strategies/StrategyFactory.sol";
import "src/test/utils/EigenLayerUnitTestSetup.sol";
import "../../contracts/permissions/PauserRegistry.sol";

/**
 * @notice Unit testing of the AVSDirectory contract. An AVSs' service manager contract will
 * call this to register an operator with the AVS.
 * Contracts tested: AVSDirectory
 * Contracts not mocked: DelegationManager
 */
contract StrategyFactoryUnitTests is EigenLayerUnitTestSetup {
    // Contract under test
    StrategyFactory public strategyFactory;
    StrategyFactory public strategyFactoryImplementation;

    // Contract dependencies
    StrategyBase public strategyImplementation;
    // eigenLayerProxyAdmin gets deployed in EigenLayerUnitTestSetup
    // ProxyAdmin eigenLayerProxyAdmin;
    ERC20PresetFixedSupply public underlyingToken;

    uint256 initialSupply = 1e36;
    address initialOwner = address(this);

    uint256 initialPausedStatus = 0;

    function setUp() virtual override public {
        EigenLayerUnitTestSetup.setUp();

        address[] memory pausers = new address[](1);
        pausers[0] = pauser;
        pauserRegistry = new PauserRegistry(pausers, unpauser);

        underlyingToken = new ERC20PresetFixedSupply("Test Token", "TEST", initialSupply, initialOwner);

        strategyImplementation = new StrategyBase(strategyManagerMock);

        strategyFactoryImplementation = new StrategyFactory(strategyManagerMock);

        strategyFactory = StrategyFactory(
            address(
                new TransparentUpgradeableProxy(
                    address(strategyFactoryImplementation),
                    address(eigenLayerProxyAdmin),
                    abi.encodeWithSelector(StrategyFactory.initialize.selector,
                        initialOwner,
                        pauserRegistry,
                        initialPausedStatus,
                        strategyImplementation,
                        eigenLayerProxyAdmin
                    )
                )
            )
        );
    }

    function test_initialization() public {
        assertEq(
            address(strategyFactory.strategyManager()),
            address(strategyManagerMock),
            "constructor / initializer incorrect, strategyManager set wrong"
        );
        assertEq(
            address(strategyFactory.strategyImplementation()),
            address(strategyImplementation),
            "constructor / initializer incorrect, strategyImplementation set wrong"
        );
        assertEq(
            address(strategyFactory.eigenLayerProxyAdmin()),
            address(eigenLayerProxyAdmin),
            "constructor / initializer incorrect, eigenLayerProxyAdmin set wrong"
        );
        assertEq(
            address(strategyFactory.pauserRegistry()),
            address(pauserRegistry),
            "constructor / initializer incorrect, pauserRegistry set wrong"
        );
        assertEq(strategyFactory.owner(), initialOwner, "constructor / initializer incorrect, owner set wrong");
        assertEq(strategyFactory.paused(), initialPausedStatus, "constructor / initializer incorrect, paused status set wrong");
    }

    function test_initialize_revert_reinitialization() public {
        cheats.expectRevert("Initializable: contract is already initialized");
        strategyFactory.initialize(
            initialOwner,
            pauserRegistry,
            initialPausedStatus,
            strategyImplementation,
            eigenLayerProxyAdmin
        );
    }

    function test_deployNewStrategy() public {
        StrategyBase newStrategy = StrategyBase(address(strategyFactory.deployNewStrategy(underlyingToken)));

        require(strategyFactory.tokenStrategies(underlyingToken) == newStrategy, "tokenStrategies mapping not set correctly");
        require(newStrategy.strategyManager() == strategyManagerMock, "strategyManager not set correctly");
        require(eigenLayerProxyAdmin.getProxyImplementation(TransparentUpgradeableProxy(payable(address(newStrategy))))
            == address(strategyImplementation),
            "strategyImplementation not set correctly");
        require(newStrategy.pauserRegistry() == pauserRegistry, "pauserRegistry not set correctly");
        require(newStrategy.underlyingToken() == underlyingToken, "underlyingToken not set correctly");
        require(strategyManagerMock.strategyIsWhitelistedForDeposit(newStrategy), "underlyingToken is not whitelisted");
        require(!strategyManagerMock.thirdPartyTransfersForbidden(newStrategy), "newStrategy has 3rd party transfers forbidden");
    }

    function test_deployNewStrategy_revert_StrategyAlreadyExists() public {
        test_deployNewStrategy();
        cheats.expectRevert("StrategyFactory.deployNewStrategy: Strategy already exists for token");
        strategyFactory.deployNewStrategy(underlyingToken);
    }

    function test_whitelistStrategies() public {
        StrategyBase strategy = StrategyBase(
            address(
                new TransparentUpgradeableProxy(
                    address(strategyImplementation),
                    address(eigenLayerProxyAdmin),
                    abi.encodeWithSelector(StrategyBase.initialize.selector, underlyingToken, pauserRegistry)
                )
            )
        );


        IStrategy[] memory strategiesToWhitelist = new IStrategy[](1);
        bool[] memory thirdPartyTransfersForbiddenValues = new bool[](1);
        strategiesToWhitelist[0] = strategy;
        thirdPartyTransfersForbiddenValues[0] = true;
        strategyFactory.whitelistStrategies(strategiesToWhitelist, thirdPartyTransfersForbiddenValues);

        require(strategyFactory.tokenStrategies(underlyingToken) == strategy, "tokenStrategies mapping not set correctly");
        require(strategyManagerMock.thirdPartyTransfersForbidden(strategy), "3rd party transfers forbidden not set correctly");
    }
}