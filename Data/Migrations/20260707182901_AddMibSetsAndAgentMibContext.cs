using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ptlk.RedisSnmp.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddMibSetsAndAgentMibContext : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_mib_nodes_version_name_numeric_oid",
                table: "mib_nodes");

            migrationBuilder.AddColumn<string>(
                name: "mib_access",
                table: "snmp_point_configs",
                type: "TEXT",
                maxLength: 40,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "mib_description",
                table: "snmp_point_configs",
                type: "TEXT",
                maxLength: 4000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "mib_module",
                table: "snmp_point_configs",
                type: "TEXT",
                maxLength: 160,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "mib_set_id_used_for_mapping",
                table: "snmp_point_configs",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "mib_syntax",
                table: "snmp_point_configs",
                type: "TEXT",
                maxLength: 80,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "polling_rate_ms",
                table: "snmp_point_configs",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "preferred_mib_set_id",
                table: "snmp_agent_configs",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "mib_file_id",
                table: "mib_nodes",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "mib_set_id",
                table: "mib_nodes",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "mib_set_id",
                table: "mib_import_jobs",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "mib_sets",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_mib_sets", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "mib_files",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    mib_set_id = table.Column<int>(type: "INTEGER", nullable: false),
                    file_name = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    stored_path = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    module_name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    module_identity_oid = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    validation_status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    error_message = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    raw_content = table.Column<string>(type: "TEXT", nullable: true),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_mib_files", x => x.id);
                    table.ForeignKey(
                        name: "fk_mib_files_mib_sets_mib_set_id",
                        column: x => x.mib_set_id,
                        principalTable: "mib_sets",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "mib_set_validation_issues",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    mib_set_id = table.Column<int>(type: "INTEGER", nullable: false),
                    severity = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    code = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    message = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    module_name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    numeric_oid = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    symbolic_name = table.Column<string>(type: "TEXT", maxLength: 240, nullable: true),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_mib_set_validation_issues", x => x.id);
                    table.ForeignKey(
                        name: "fk_mib_set_validation_issues_mib_sets_mib_set_id",
                        column: x => x.mib_set_id,
                        principalTable: "mib_sets",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_snmp_point_configs_mib_set_id_used_for_mapping",
                table: "snmp_point_configs",
                column: "mib_set_id_used_for_mapping");

            migrationBuilder.CreateIndex(
                name: "ix_snmp_agent_configs_preferred_mib_set_id",
                table: "snmp_agent_configs",
                column: "preferred_mib_set_id");

            migrationBuilder.CreateIndex(
                name: "ix_mib_nodes_mib_file_id",
                table: "mib_nodes",
                column: "mib_file_id");

            migrationBuilder.CreateIndex(
                name: "ix_mib_nodes_mib_set_id_numeric_oid",
                table: "mib_nodes",
                columns: new[] { "mib_set_id", "numeric_oid" });

            migrationBuilder.CreateIndex(
                name: "ix_mib_nodes_mib_set_id_symbolic_name",
                table: "mib_nodes",
                columns: new[] { "mib_set_id", "symbolic_name" });

            migrationBuilder.CreateIndex(
                name: "ix_mib_nodes_version_name_numeric_oid",
                table: "mib_nodes",
                columns: new[] { "version_name", "numeric_oid" });

            migrationBuilder.CreateIndex(
                name: "ix_mib_import_jobs_mib_set_id",
                table: "mib_import_jobs",
                column: "mib_set_id");

            migrationBuilder.CreateIndex(
                name: "ix_mib_files_hash",
                table: "mib_files",
                column: "hash");

            migrationBuilder.CreateIndex(
                name: "ix_mib_files_mib_set_id_file_name",
                table: "mib_files",
                columns: new[] { "mib_set_id", "file_name" });

            migrationBuilder.CreateIndex(
                name: "ix_mib_set_validation_issues_mib_set_id_code",
                table: "mib_set_validation_issues",
                columns: new[] { "mib_set_id", "code" });

            migrationBuilder.CreateIndex(
                name: "ix_mib_set_validation_issues_mib_set_id_severity",
                table: "mib_set_validation_issues",
                columns: new[] { "mib_set_id", "severity" });

            migrationBuilder.CreateIndex(
                name: "ix_mib_sets_name",
                table: "mib_sets",
                column: "name",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "fk_mib_import_jobs_mib_sets_mib_set_id",
                table: "mib_import_jobs",
                column: "mib_set_id",
                principalTable: "mib_sets",
                principalColumn: "id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "fk_mib_nodes_mib_files_mib_file_id",
                table: "mib_nodes",
                column: "mib_file_id",
                principalTable: "mib_files",
                principalColumn: "id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "fk_mib_nodes_mib_sets_mib_set_id",
                table: "mib_nodes",
                column: "mib_set_id",
                principalTable: "mib_sets",
                principalColumn: "id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "fk_snmp_agent_configs_mib_sets_preferred_mib_set_id",
                table: "snmp_agent_configs",
                column: "preferred_mib_set_id",
                principalTable: "mib_sets",
                principalColumn: "id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "fk_snmp_point_configs_mib_sets_mib_set_id_used_for_mapping",
                table: "snmp_point_configs",
                column: "mib_set_id_used_for_mapping",
                principalTable: "mib_sets",
                principalColumn: "id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "fk_mib_import_jobs_mib_sets_mib_set_id",
                table: "mib_import_jobs");

            migrationBuilder.DropForeignKey(
                name: "fk_mib_nodes_mib_files_mib_file_id",
                table: "mib_nodes");

            migrationBuilder.DropForeignKey(
                name: "fk_mib_nodes_mib_sets_mib_set_id",
                table: "mib_nodes");

            migrationBuilder.DropForeignKey(
                name: "fk_snmp_agent_configs_mib_sets_preferred_mib_set_id",
                table: "snmp_agent_configs");

            migrationBuilder.DropForeignKey(
                name: "fk_snmp_point_configs_mib_sets_mib_set_id_used_for_mapping",
                table: "snmp_point_configs");

            migrationBuilder.DropTable(
                name: "mib_files");

            migrationBuilder.DropTable(
                name: "mib_set_validation_issues");

            migrationBuilder.DropTable(
                name: "mib_sets");

            migrationBuilder.DropIndex(
                name: "ix_snmp_point_configs_mib_set_id_used_for_mapping",
                table: "snmp_point_configs");

            migrationBuilder.DropIndex(
                name: "ix_snmp_agent_configs_preferred_mib_set_id",
                table: "snmp_agent_configs");

            migrationBuilder.DropIndex(
                name: "ix_mib_nodes_mib_file_id",
                table: "mib_nodes");

            migrationBuilder.DropIndex(
                name: "ix_mib_nodes_mib_set_id_numeric_oid",
                table: "mib_nodes");

            migrationBuilder.DropIndex(
                name: "ix_mib_nodes_mib_set_id_symbolic_name",
                table: "mib_nodes");

            migrationBuilder.DropIndex(
                name: "ix_mib_nodes_version_name_numeric_oid",
                table: "mib_nodes");

            migrationBuilder.DropIndex(
                name: "ix_mib_import_jobs_mib_set_id",
                table: "mib_import_jobs");

            migrationBuilder.DropColumn(
                name: "mib_access",
                table: "snmp_point_configs");

            migrationBuilder.DropColumn(
                name: "mib_description",
                table: "snmp_point_configs");

            migrationBuilder.DropColumn(
                name: "mib_module",
                table: "snmp_point_configs");

            migrationBuilder.DropColumn(
                name: "mib_set_id_used_for_mapping",
                table: "snmp_point_configs");

            migrationBuilder.DropColumn(
                name: "mib_syntax",
                table: "snmp_point_configs");

            migrationBuilder.DropColumn(
                name: "polling_rate_ms",
                table: "snmp_point_configs");

            migrationBuilder.DropColumn(
                name: "preferred_mib_set_id",
                table: "snmp_agent_configs");

            migrationBuilder.DropColumn(
                name: "mib_file_id",
                table: "mib_nodes");

            migrationBuilder.DropColumn(
                name: "mib_set_id",
                table: "mib_nodes");

            migrationBuilder.DropColumn(
                name: "mib_set_id",
                table: "mib_import_jobs");

            migrationBuilder.CreateIndex(
                name: "ix_mib_nodes_version_name_numeric_oid",
                table: "mib_nodes",
                columns: new[] { "version_name", "numeric_oid" },
                unique: true);
        }
    }
}
