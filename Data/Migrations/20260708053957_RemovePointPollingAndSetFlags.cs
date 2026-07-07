using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ptlk.RedisSnmp.Data.Migrations
{
    /// <inheritdoc />
    public partial class RemovePointPollingAndSetFlags : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "poll_enabled",
                table: "snmp_point_configs");

            migrationBuilder.DropColumn(
                name: "polling_rate_ms",
                table: "snmp_point_configs");

            migrationBuilder.DropColumn(
                name: "set_enabled",
                table: "snmp_point_configs");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "poll_enabled",
                table: "snmp_point_configs",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "polling_rate_ms",
                table: "snmp_point_configs",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "set_enabled",
                table: "snmp_point_configs",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);
        }
    }
}
