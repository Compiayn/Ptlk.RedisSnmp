using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ptlk.RedisSnmp.Data.Migrations
{
    /// <inheritdoc />
    public partial class RemovePointMappingMibSet : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "fk_snmp_point_configs_mib_sets_mib_set_id_used_for_mapping",
                table: "snmp_point_configs");

            migrationBuilder.DropIndex(
                name: "ix_snmp_point_configs_mib_set_id_used_for_mapping",
                table: "snmp_point_configs");

            migrationBuilder.DropColumn(
                name: "mib_set_id_used_for_mapping",
                table: "snmp_point_configs");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "mib_set_id_used_for_mapping",
                table: "snmp_point_configs",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "ix_snmp_point_configs_mib_set_id_used_for_mapping",
                table: "snmp_point_configs",
                column: "mib_set_id_used_for_mapping");

            migrationBuilder.AddForeignKey(
                name: "fk_snmp_point_configs_mib_sets_mib_set_id_used_for_mapping",
                table: "snmp_point_configs",
                column: "mib_set_id_used_for_mapping",
                principalTable: "mib_sets",
                principalColumn: "id",
                onDelete: ReferentialAction.SetNull);
        }
    }
}
