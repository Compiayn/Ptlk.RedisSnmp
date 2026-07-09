using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ptlk.RedisSnmp.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddTrapReceiverSecurity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_snmp_trap_log_entries_agent_id_trap_oid",
                table: "snmp_trap_log_entries");

            migrationBuilder.AlterColumn<string>(
                name: "agent_id",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 160,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "TEXT",
                oldMaxLength: 160);

            migrationBuilder.AddColumn<string>(
                name: "agent_resolution_reason",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 120,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "agent_resolution_result",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 32,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "credential_validation_reason",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 120,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "credential_validation_result",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 32,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "expected_object_match_result",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "expected_objects",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "publish_mode",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 32,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "publish_reason",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 120,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "publish_result",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 32,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "resolved_agent_id",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 160,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "resolved_payload",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "resolved_trap_description",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 4000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "resolved_trap_module",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 160,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "resolved_trap_name",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 240,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "resolved_trap_oid",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 160,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "transport_source_port",
                table: "snmp_trap_log_entries",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "trap_credential_config_id",
                table: "snmp_agent_configs",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "node_kind",
                table: "mib_nodes",
                type: "TEXT",
                maxLength: 64,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "mib_notification_objects",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    notification_mib_node_id = table.Column<int>(type: "INTEGER", nullable: false),
                    sort_order = table.Column<int>(type: "INTEGER", nullable: false),
                    object_symbol = table.Column<string>(type: "TEXT", maxLength: 240, nullable: false),
                    object_oid = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_mib_notification_objects", x => x.id);
                    table.ForeignKey(
                        name: "fk_mib_notification_objects_mib_nodes_notification_mib_node_id",
                        column: x => x.notification_mib_node_id,
                        principalTable: "mib_nodes",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "snmp_trap_credential_configs",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    version = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    protected_community = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    security_name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    security_level = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    auth_protocol = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    protected_auth_password = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    priv_protocol = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    protected_priv_password = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    engine_id = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_snmp_trap_credential_configs", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_snmp_trap_log_entries_resolved_agent_id_resolved_trap_oid",
                table: "snmp_trap_log_entries",
                columns: new[] { "resolved_agent_id", "resolved_trap_oid" });

            migrationBuilder.CreateIndex(
                name: "ix_snmp_agent_configs_trap_credential_config_id",
                table: "snmp_agent_configs",
                column: "trap_credential_config_id");

            migrationBuilder.CreateIndex(
                name: "ix_mib_notification_objects_notification_mib_node_id_sort_order",
                table: "mib_notification_objects",
                columns: new[] { "notification_mib_node_id", "sort_order" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_snmp_trap_credential_configs_name",
                table: "snmp_trap_credential_configs",
                column: "name",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "fk_snmp_agent_configs_snmp_trap_credential_configs_trap_credential_config_id",
                table: "snmp_agent_configs",
                column: "trap_credential_config_id",
                principalTable: "snmp_trap_credential_configs",
                principalColumn: "id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "fk_snmp_agent_configs_snmp_trap_credential_configs_trap_credential_config_id",
                table: "snmp_agent_configs");

            migrationBuilder.DropTable(
                name: "mib_notification_objects");

            migrationBuilder.DropTable(
                name: "snmp_trap_credential_configs");

            migrationBuilder.DropIndex(
                name: "ix_snmp_trap_log_entries_resolved_agent_id_resolved_trap_oid",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropIndex(
                name: "ix_snmp_agent_configs_trap_credential_config_id",
                table: "snmp_agent_configs");

            migrationBuilder.DropColumn(
                name: "agent_resolution_reason",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "agent_resolution_result",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "credential_validation_reason",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "credential_validation_result",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "expected_object_match_result",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "expected_objects",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "publish_mode",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "publish_reason",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "publish_result",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "resolved_agent_id",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "resolved_payload",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "resolved_trap_description",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "resolved_trap_module",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "resolved_trap_name",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "resolved_trap_oid",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "transport_source_port",
                table: "snmp_trap_log_entries");

            migrationBuilder.DropColumn(
                name: "trap_credential_config_id",
                table: "snmp_agent_configs");

            migrationBuilder.DropColumn(
                name: "node_kind",
                table: "mib_nodes");

            migrationBuilder.AlterColumn<string>(
                name: "agent_id",
                table: "snmp_trap_log_entries",
                type: "TEXT",
                maxLength: 160,
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "TEXT",
                oldMaxLength: 160,
                oldNullable: true);

            migrationBuilder.CreateIndex(
                name: "ix_snmp_trap_log_entries_agent_id_trap_oid",
                table: "snmp_trap_log_entries",
                columns: new[] { "agent_id", "trap_oid" });
        }
    }
}
