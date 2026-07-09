using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ptlk.RedisSnmp.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddExpressions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "expression_configs",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    rw = table.Column<string>(type: "TEXT", maxLength: 8, nullable: false),
                    value_type = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false, defaultValue: "double"),
                    read_return_parameter = table.Column<string>(type: "TEXT", maxLength: 120, nullable: true),
                    read_script = table.Column<string>(type: "TEXT", nullable: true),
                    write_input_parameter = table.Column<string>(type: "TEXT", maxLength: 120, nullable: true),
                    write_script = table.Column<string>(type: "TEXT", nullable: true),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_expression_configs", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "expression_bindings",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    expression_config_id = table.Column<int>(type: "INTEGER", nullable: false),
                    parameter_name = table.Column<string>(type: "TEXT", maxLength: 120, nullable: false),
                    source_path = table.Column<string>(type: "TEXT", maxLength: 320, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_expression_bindings", x => x.id);
                    table.ForeignKey(
                        name: "fk_expression_bindings_expression_configs_expression_config_id",
                        column: x => x.expression_config_id,
                        principalTable: "expression_configs",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_expression_bindings_expression_config_id_parameter_name",
                table: "expression_bindings",
                columns: new[] { "expression_config_id", "parameter_name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_expression_configs_name",
                table: "expression_configs",
                column: "name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "expression_bindings");

            migrationBuilder.DropTable(
                name: "expression_configs");
        }
    }
}
