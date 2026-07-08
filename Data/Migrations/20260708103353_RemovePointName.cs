using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ptlk.RedisSnmp.Data.Migrations
{
    /// <inheritdoc />
    public partial class RemovePointName : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_snmp_point_configs_agent_config_id_point_name",
                table: "snmp_point_configs");

            migrationBuilder.DropColumn(
                name: "point_name",
                table: "snmp_point_configs");

            migrationBuilder.CreateIndex(
                name: "ix_snmp_point_configs_agent_config_id",
                table: "snmp_point_configs",
                column: "agent_config_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_snmp_point_configs_agent_config_id",
                table: "snmp_point_configs");

            migrationBuilder.AddColumn<string>(
                name: "point_name",
                table: "snmp_point_configs",
                type: "TEXT",
                maxLength: 160,
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "ix_snmp_point_configs_agent_config_id_point_name",
                table: "snmp_point_configs",
                columns: new[] { "agent_config_id", "point_name" },
                unique: true);
        }
    }
}
