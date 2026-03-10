using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CybexNode.Api.Migrations
{
    /// <inheritdoc />
    public partial class AddCveEntries : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CveEntries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CveId = table.Column<string>(type: "nvarchar(30)", maxLength: 30, nullable: false),
                    VendorProject = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Product = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    VulnerabilityName = table.Column<string>(type: "nvarchar(300)", maxLength: 300, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Severity = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: false),
                    RequiredAction = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DueDate = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CveEntries", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CveEntries_CveId",
                table: "CveEntries",
                column: "CveId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CveEntries");
        }
    }
}
