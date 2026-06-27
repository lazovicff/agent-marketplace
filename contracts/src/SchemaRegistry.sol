// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SchemaRegistry
/// @notice Registry of zkTLS schemas. Each schema defines the structure of a
///         TLS request and the response fields to extract. Schemas are used
///         by the zkTLS prover to know what to prove — they do NOT define
///         the circuit or verification key (there is one universal circuit).
contract SchemaRegistry {
    // =========================================================
    //  Types
    // =========================================================

    struct Schema {
        uint256 id;
        string name;
        string description;
        string serverHost;
        string requestSchema; // JSON schema for the HTTP request
        string responseSchema; // JSON schema for the HTTP response fields
        address creator;
        uint256 createdAt;
        bool active;
    }

    // =========================================================
    //  State
    // =========================================================

    /// @notice schema ID → Schema
    mapping(uint256 => Schema) public schemas;

    /// @notice Total number of schemas (ever created, including inactive).
    uint256 public schemaCount;

    // =========================================================
    //  Events
    // =========================================================

    event SchemaAdded(
        uint256 indexed schemaId,
        string name,
        string serverHost,
        address indexed creator,
        uint256 timestamp
    );

    event SchemaUpdated(uint256 indexed schemaId, uint256 timestamp);

    event SchemaDeactivated(uint256 indexed schemaId, uint256 timestamp);

    // =========================================================
    //  Errors
    // =========================================================

    error SchemaRegistry__NotCreator();
    error SchemaRegistry__SchemaInactive();
    error SchemaRegistry__EmptyName();
    error SchemaRegistry__EmptyServerHost();

    // =========================================================
    //  Modifiers
    // =========================================================

    modifier onlyCreator(uint256 schemaId) {
        if (schemas[schemaId].creator != msg.sender) {
            revert SchemaRegistry__NotCreator();
        }
        _;
    }

    // =========================================================
    //  Schema Management
    // =========================================================

    /// @notice Add a new zkTLS schema. No verification key needed — the
    ///         universal zkTLS circuit handles all schemas.
    /// @param name Human-readable name (e.g. "github-stars").
    /// @param description Human-readable description.
    /// @param serverHost TLS server hostname (e.g. "api.github.com").
    /// @param requestSchema JSON schema for the HTTP request.
    /// @param responseSchema JSON schema for the HTTP response fields.
    /// @return schemaId The assigned schema ID.
    function addSchema(
        string calldata name,
        string calldata description,
        string calldata serverHost,
        string calldata requestSchema,
        string calldata responseSchema
    ) external returns (uint256 schemaId) {
        if (bytes(name).length == 0) revert SchemaRegistry__EmptyName();
        if (bytes(serverHost).length == 0)
            revert SchemaRegistry__EmptyServerHost();

        schemaId = ++schemaCount;

        schemas[schemaId] = Schema({
            id: schemaId,
            name: name,
            description: description,
            serverHost: serverHost,
            requestSchema: requestSchema,
            responseSchema: responseSchema,
            creator: msg.sender,
            createdAt: block.timestamp,
            active: true
        });

        emit SchemaAdded(
            schemaId,
            name,
            serverHost,
            msg.sender,
            block.timestamp
        );
    }

    /// @notice Update an existing schema's metadata.
    function updateSchema(
        uint256 schemaId,
        string calldata name,
        string calldata description,
        string calldata serverHost,
        string calldata requestSchema,
        string calldata responseSchema
    ) external onlyCreator(schemaId) {
        if (!schemas[schemaId].active) revert SchemaRegistry__SchemaInactive();

        Schema storage s = schemas[schemaId];
        s.name = name;
        s.description = description;
        s.serverHost = serverHost;
        s.requestSchema = requestSchema;
        s.responseSchema = responseSchema;

        emit SchemaUpdated(schemaId, block.timestamp);
    }

    /// @notice Deactivate a schema.
    function deactivateSchema(uint256 schemaId) external onlyCreator(schemaId) {
        if (!schemas[schemaId].active) revert SchemaRegistry__SchemaInactive();
        schemas[schemaId].active = false;
        emit SchemaDeactivated(schemaId, block.timestamp);
    }

    // =========================================================
    //  View Functions
    // =========================================================

    function getSchema(uint256 schemaId) external view returns (Schema memory) {
        return schemas[schemaId];
    }

    function isActive(uint256 schemaId) external view returns (bool) {
        return schemas[schemaId].active;
    }

    function getSchemaCount() external view returns (uint256) {
        return schemaCount;
    }
}
