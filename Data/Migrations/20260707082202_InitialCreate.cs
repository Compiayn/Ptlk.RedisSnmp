using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ptlk.RedisSnmp.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "command_executions",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    command_id = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    redis_key = table.Column<string>(type: "TEXT", maxLength: 320, nullable: false),
                    requested_payload = table.Column<string>(type: "TEXT", nullable: false),
                    result_payload = table.Column<string>(type: "TEXT", nullable: true),
                    error_code = table.Column<string>(type: "TEXT", maxLength: 80, nullable: true),
                    error_message = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_command_executions", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "mib_import_jobs",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    import_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    version_name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    source_file_name = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    error_message = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_mib_import_jobs", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "mib_nodes",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    version_name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    numeric_oid = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    symbolic_name = table.Column<string>(type: "TEXT", maxLength: 240, nullable: true),
                    module_name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    syntax = table.Column<string>(type: "TEXT", maxLength: 80, nullable: true),
                    access = table.Column<string>(type: "TEXT", maxLength: 40, nullable: true),
                    description = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    active = table.Column<bool>(type: "INTEGER", nullable: false),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_mib_nodes", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "redis_mappings",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    source_path = table.Column<string>(type: "TEXT", maxLength: 320, nullable: false),
                    redis_key = table.Column<string>(type: "TEXT", maxLength: 320, nullable: false),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_redis_mappings", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "snmp_credential_configs",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    version = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    protected_community = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    security_name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    security_level = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    auth_protocol = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    protected_auth_password = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    priv_protocol = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    protected_priv_password = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_snmp_credential_configs", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "snmp_trap_log_entries",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    received_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    agent_id = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    source_address = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    trap_oid = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    varbinds_json = table.Column<string>(type: "TEXT", nullable: false),
                    mib_labels_json = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    raw_payload = table.Column<string>(type: "TEXT", maxLength: 8000, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_snmp_trap_log_entries", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "snmp_trap_rule_configs",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    agent_id = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    trap_oid = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    display_name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_snmp_trap_rule_configs", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "system_log_entries",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    category = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    level = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    message = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    command_id = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_system_log_entries", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "snmp_agent_configs",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    agent_id = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    display_name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    host = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    port = table.Column<int>(type: "INTEGER", nullable: false),
                    snmp_version = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    credential_config_id = table.Column<int>(type: "INTEGER", nullable: true),
                    timeout_ms = table.Column<int>(type: "INTEGER", nullable: false),
                    retry_count = table.Column<int>(type: "INTEGER", nullable: false),
                    polling_rate_ms = table.Column<int>(type: "INTEGER", nullable: false),
                    enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_snmp_agent_configs", x => x.id);
                    table.ForeignKey(
                        name: "fk_snmp_agent_configs_snmp_credential_configs_credential_config_id",
                        column: x => x.credential_config_id,
                        principalTable: "snmp_credential_configs",
                        principalColumn: "id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "snmp_point_configs",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    agent_config_id = table.Column<int>(type: "INTEGER", nullable: false),
                    point_name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    source_path = table.Column<string>(type: "TEXT", maxLength: 320, nullable: false),
                    numeric_oid = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    value_type = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    poll_enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    set_enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    access = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    mib_label = table.Column<string>(type: "TEXT", maxLength: 240, nullable: true),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_snmp_point_configs", x => x.id);
                    table.ForeignKey(
                        name: "fk_snmp_point_configs_snmp_agent_configs_agent_config_id",
                        column: x => x.agent_config_id,
                        principalTable: "snmp_agent_configs",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "snmp_log_entries",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    agent_config_id = table.Column<int>(type: "INTEGER", nullable: true),
                    point_config_id = table.Column<int>(type: "INTEGER", nullable: true),
                    agent_id = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    numeric_oid = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    operation = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    level = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    message = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    command_id = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    error_code = table.Column<string>(type: "TEXT", maxLength: 80, nullable: true),
                    duration_ms = table.Column<int>(type: "INTEGER", nullable: true),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_snmp_log_entries", x => x.id);
                    table.ForeignKey(
                        name: "fk_snmp_log_entries_snmp_agent_configs_agent_config_id",
                        column: x => x.agent_config_id,
                        principalTable: "snmp_agent_configs",
                        principalColumn: "id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "fk_snmp_log_entries_snmp_point_configs_point_config_id",
                        column: x => x.point_config_id,
                        principalTable: "snmp_point_configs",
                        principalColumn: "id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "ix_command_executions_command_id",
                table: "command_executions",
                column: "command_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_command_executions_redis_key",
                table: "command_executions",
                column: "redis_key");

            migrationBuilder.CreateIndex(
                name: "ix_mib_import_jobs_import_id",
                table: "mib_import_jobs",
                column: "import_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_mib_nodes_symbolic_name",
                table: "mib_nodes",
                column: "symbolic_name");

            migrationBuilder.CreateIndex(
                name: "ix_mib_nodes_version_name_numeric_oid",
                table: "mib_nodes",
                columns: new[] { "version_name", "numeric_oid" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_redis_mappings_redis_key",
                table: "redis_mappings",
                column: "redis_key",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_redis_mappings_source_path",
                table: "redis_mappings",
                column: "source_path",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_snmp_agent_configs_agent_id",
                table: "snmp_agent_configs",
                column: "agent_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_snmp_agent_configs_credential_config_id",
                table: "snmp_agent_configs",
                column: "credential_config_id");

            migrationBuilder.CreateIndex(
                name: "ix_snmp_agent_configs_display_name",
                table: "snmp_agent_configs",
                column: "display_name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_snmp_credential_configs_name",
                table: "snmp_credential_configs",
                column: "name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_snmp_log_entries_agent_config_id",
                table: "snmp_log_entries",
                column: "agent_config_id");

            migrationBuilder.CreateIndex(
                name: "ix_snmp_log_entries_agent_id_numeric_oid",
                table: "snmp_log_entries",
                columns: new[] { "agent_id", "numeric_oid" });

            migrationBuilder.CreateIndex(
                name: "ix_snmp_log_entries_command_id",
                table: "snmp_log_entries",
                column: "command_id");

            migrationBuilder.CreateIndex(
                name: "ix_snmp_log_entries_created_at",
                table: "snmp_log_entries",
                column: "created_at");

            migrationBuilder.CreateIndex(
                name: "ix_snmp_log_entries_point_config_id",
                table: "snmp_log_entries",
                column: "point_config_id");

            migrationBuilder.CreateIndex(
                name: "ix_snmp_point_configs_agent_config_id_point_name",
                table: "snmp_point_configs",
                columns: new[] { "agent_config_id", "point_name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_snmp_point_configs_source_path",
                table: "snmp_point_configs",
                column: "source_path",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_snmp_trap_log_entries_agent_id_trap_oid",
                table: "snmp_trap_log_entries",
                columns: new[] { "agent_id", "trap_oid" });

            migrationBuilder.CreateIndex(
                name: "ix_snmp_trap_log_entries_received_at",
                table: "snmp_trap_log_entries",
                column: "received_at");

            migrationBuilder.CreateIndex(
                name: "ix_snmp_trap_rule_configs_agent_id_trap_oid",
                table: "snmp_trap_rule_configs",
                columns: new[] { "agent_id", "trap_oid" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_system_log_entries_category_level",
                table: "system_log_entries",
                columns: new[] { "category", "level" });

            migrationBuilder.CreateIndex(
                name: "ix_system_log_entries_command_id",
                table: "system_log_entries",
                column: "command_id");

            migrationBuilder.CreateIndex(
                name: "ix_system_log_entries_created_at",
                table: "system_log_entries",
                column: "created_at");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "command_executions");

            migrationBuilder.DropTable(
                name: "mib_import_jobs");

            migrationBuilder.DropTable(
                name: "mib_nodes");

            migrationBuilder.DropTable(
                name: "redis_mappings");

            migrationBuilder.DropTable(
                name: "snmp_log_entries");

            migrationBuilder.DropTable(
                name: "snmp_trap_log_entries");

            migrationBuilder.DropTable(
                name: "snmp_trap_rule_configs");

            migrationBuilder.DropTable(
                name: "system_log_entries");

            migrationBuilder.DropTable(
                name: "snmp_point_configs");

            migrationBuilder.DropTable(
                name: "snmp_agent_configs");

            migrationBuilder.DropTable(
                name: "snmp_credential_configs");
        }
    }
}
