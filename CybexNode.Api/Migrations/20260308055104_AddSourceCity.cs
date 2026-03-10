using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CybexNode.Api.Migrations
{
    /// <inheritdoc />
    public partial class AddSourceCity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "SourceCity",
                table: "Incidents",
                type: "nvarchar(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "SourceCity",
                table: "Incidents");
        }
    }
}
