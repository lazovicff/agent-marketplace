// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";

contract SchemaRegistryTest is Test {
    SchemaRegistry public registry;

    string constant NAME = "github-stars";
    string constant DESC = "Proves a GitHub repo has at least N stars";
    string constant HOST = "api.github.com";
    string constant REQ_SCHEMA = '{"method":"GET","path":"/repos/owner/repo"}';
    string constant RES_SCHEMA =
        '{"type":"object","properties":{"stargazers_count":{"type":"integer"}}}';

    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");

    function setUp() public {
        registry = new SchemaRegistry();
    }

    // =========================================================
    //  addSchema
    // =========================================================

    function test_AddSchema() public {
        vm.prank(alice);
        uint256 id = registry.addSchema(
            NAME,
            DESC,
            HOST,
            REQ_SCHEMA,
            RES_SCHEMA
        );

        assertEq(id, 1);
        assertEq(registry.schemaCount(), 1);

        SchemaRegistry.Schema memory s = registry.getSchema(id);
        assertEq(s.id, 1);
        assertEq(s.name, NAME);
        assertEq(s.description, DESC);
        assertEq(s.serverHost, HOST);
        assertEq(s.requestSchema, REQ_SCHEMA);
        assertEq(s.responseSchema, RES_SCHEMA);
        assertEq(s.creator, alice);
        assertTrue(s.active);
        assertEq(s.createdAt, block.timestamp);
    }

    function test_AddSchemaMultiple() public {
        vm.prank(alice);
        registry.addSchema(NAME, DESC, HOST, REQ_SCHEMA, RES_SCHEMA);

        vm.prank(bob);
        uint256 id2 = registry.addSchema(
            "twitter-followers",
            DESC,
            "api.twitter.com",
            REQ_SCHEMA,
            RES_SCHEMA
        );

        assertEq(id2, 2);
        assertEq(registry.schemaCount(), 2);
    }

    function test_RevertWhen_EmptyName() public {
        vm.prank(alice);
        vm.expectRevert(SchemaRegistry.SchemaRegistry__EmptyName.selector);
        registry.addSchema("", DESC, HOST, REQ_SCHEMA, RES_SCHEMA);
    }

    function test_RevertWhen_EmptyServerHost() public {
        vm.prank(alice);
        vm.expectRevert(
            SchemaRegistry.SchemaRegistry__EmptyServerHost.selector
        );
        registry.addSchema(NAME, DESC, "", REQ_SCHEMA, RES_SCHEMA);
    }

    // =========================================================
    //  updateSchema
    // =========================================================

    function test_UpdateSchema() public {
        vm.prank(alice);
        uint256 id = registry.addSchema(
            NAME,
            DESC,
            HOST,
            REQ_SCHEMA,
            RES_SCHEMA
        );

        vm.prank(alice);
        registry.updateSchema(
            id,
            "new-name",
            "new-desc",
            "new.host.com",
            "{}",
            "{}"
        );

        SchemaRegistry.Schema memory s = registry.getSchema(id);
        assertEq(s.name, "new-name");
        assertEq(s.description, "new-desc");
        assertEq(s.serverHost, "new.host.com");
        assertEq(s.requestSchema, "{}");
        assertEq(s.responseSchema, "{}");
    }

    function test_RevertWhen_NotCreatorUpdate() public {
        vm.prank(alice);
        uint256 id = registry.addSchema(
            NAME,
            DESC,
            HOST,
            REQ_SCHEMA,
            RES_SCHEMA
        );

        vm.prank(bob);
        vm.expectRevert(SchemaRegistry.SchemaRegistry__NotCreator.selector);
        registry.updateSchema(
            id,
            "new-name",
            "new-desc",
            "new.host.com",
            "{}",
            "{}"
        );
    }

    // =========================================================
    //  deactivateSchema
    // =========================================================

    function test_DeactivateSchema() public {
        vm.prank(alice);
        uint256 id = registry.addSchema(
            NAME,
            DESC,
            HOST,
            REQ_SCHEMA,
            RES_SCHEMA
        );

        vm.prank(alice);
        registry.deactivateSchema(id);

        assertFalse(registry.isActive(id));
    }

    function test_RevertWhen_NotCreatorDeactivate() public {
        vm.prank(alice);
        uint256 id = registry.addSchema(
            NAME,
            DESC,
            HOST,
            REQ_SCHEMA,
            RES_SCHEMA
        );

        vm.prank(bob);
        vm.expectRevert(SchemaRegistry.SchemaRegistry__NotCreator.selector);
        registry.deactivateSchema(id);
    }

    function test_RevertWhen_DeactivateInactive() public {
        vm.prank(alice);
        uint256 id = registry.addSchema(
            NAME,
            DESC,
            HOST,
            REQ_SCHEMA,
            RES_SCHEMA
        );

        vm.prank(alice);
        registry.deactivateSchema(id);

        vm.prank(alice);
        vm.expectRevert(SchemaRegistry.SchemaRegistry__SchemaInactive.selector);
        registry.deactivateSchema(id);
    }

    // =========================================================
    //  View functions
    // =========================================================

    function test_GetSchemaCount() public {
        assertEq(registry.getSchemaCount(), 0);

        vm.prank(alice);
        registry.addSchema(NAME, DESC, HOST, REQ_SCHEMA, RES_SCHEMA);
        assertEq(registry.getSchemaCount(), 1);

        vm.prank(bob);
        registry.addSchema("s2", DESC, HOST, REQ_SCHEMA, RES_SCHEMA);
        assertEq(registry.getSchemaCount(), 2);
    }
}
