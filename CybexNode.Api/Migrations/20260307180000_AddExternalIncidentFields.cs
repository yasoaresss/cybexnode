using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CybexNode.Api.Migrations
{
    /// <inheritdoc />
    public partial class AddExternalIncidentFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "DataSource",
                table: "Incidents",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<double>(
                name: "Latitude",
                table: "Incidents",
                type: "float",
                nullable: true);

            migrationBuilder.AddColumn<double>(
                name: "Longitude",
                table: "Incidents",
                type: "float",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Severity",
                table: "Incidents",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SourceCountry",
                table: "Incidents",
                type: "nvarchar(10)",
                maxLength: 10,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DataSource",
                table: "Incidents");

            migrationBuilder.DropColumn(
                name: "Latitude",
                table: "Incidents");

            migrationBuilder.DropColumn(
                name: "Longitude",
                table: "Incidents");

            migrationBuilder.DropColumn(
                name: "Severity",
                table: "Incidents");

            migrationBuilder.DropColumn(
                name: "SourceCountry",
                table: "Incidents");
        }
    }
}
