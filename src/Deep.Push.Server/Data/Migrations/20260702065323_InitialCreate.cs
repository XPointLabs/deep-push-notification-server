using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Deep.Push.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Subscriptions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    IdentityKey = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Pubkey = table.Column<string>(type: "character varying(66)", maxLength: 66, nullable: false),
                    SessionEd25519 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    NamespacesJson = table.Column<string>(type: "text", nullable: false),
                    WantData = table.Column<bool>(type: "boolean", nullable: false),
                    Service = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    DeviceToken = table.Column<string>(type: "character varying(4096)", maxLength: 4096, nullable: false),
                    EncryptionKey = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    SignatureTimestamp = table.Column<long>(type: "bigint", nullable: false),
                    SubscribedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Subscriptions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Deliveries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SubscriptionId = table.Column<Guid>(type: "uuid", nullable: false),
                    MessageHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Namespace = table.Column<int>(type: "integer", nullable: false),
                    MessageTimestamp = table.Column<long>(type: "bigint", nullable: false),
                    Expiration = table.Column<long>(type: "bigint", nullable: false),
                    MessageData = table.Column<string>(type: "text", nullable: true),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    Attempts = table.Column<int>(type: "integer", nullable: false),
                    NextAttemptAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    DeliveredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ProviderMessageId = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    LastError = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Deliveries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Deliveries_Subscriptions_SubscriptionId",
                        column: x => x.SubscriptionId,
                        principalTable: "Subscriptions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Deliveries_Status_NextAttemptAt",
                table: "Deliveries",
                columns: new[] { "Status", "NextAttemptAt" });

            migrationBuilder.CreateIndex(
                name: "IX_Deliveries_SubscriptionId_MessageHash",
                table: "Deliveries",
                columns: new[] { "SubscriptionId", "MessageHash" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Subscriptions_IdentityKey",
                table: "Subscriptions",
                column: "IdentityKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Subscriptions_Pubkey",
                table: "Subscriptions",
                column: "Pubkey");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Deliveries");

            migrationBuilder.DropTable(
                name: "Subscriptions");
        }
    }
}
