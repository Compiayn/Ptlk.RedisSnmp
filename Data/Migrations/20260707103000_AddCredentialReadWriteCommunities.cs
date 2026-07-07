using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Ptlk.RedisSnmp.Data;

#nullable disable

namespace Ptlk.RedisSnmp.Data.Migrations
{
    /// <inheritdoc />
    [DbContext(typeof(AppDbContext))]
    [Migration("20260707103000_AddCredentialReadWriteCommunities")]
    public partial class AddCredentialReadWriteCommunities : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "protected_read_community",
                table: "snmp_credential_configs",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "protected_write_community",
                table: "snmp_credential_configs",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.Sql("""
                UPDATE snmp_credential_configs
                SET protected_read_community = COALESCE(protected_read_community, protected_community),
                    protected_write_community = COALESCE(protected_write_community, protected_community)
                WHERE protected_community IS NOT NULL
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "protected_read_community",
                table: "snmp_credential_configs");

            migrationBuilder.DropColumn(
                name: "protected_write_community",
                table: "snmp_credential_configs");
        }
    }
}
