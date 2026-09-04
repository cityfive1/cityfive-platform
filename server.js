async function startServer() {
  if (!process.env.MONGO_URI) {
    console.error("ERROR: MONGO_URI environment variable is missing.");
    process.exit(1);
  }

  const server = app.listen(
    PORT,
    "0.0.0.0",
    () => {
      console.log("Server running on port " + PORT);
      console.log("Platform mode: " + PLATFORM_MODE);
      console.log("Real funds enabled: false");

      connectDatabase();
    }
  );

  server.on("error", (error) => {
    console.error("HTTP server error:", error);
    process.exit(1);
  });

  async function connectDatabase() {
    try {
      await mongoose.connect(process.env.MONGO_URI);
      console.log("DB connected");
    } catch (error) {
      console.error("Database connection error:", error);
    }
  }

  async function shutdown(signal) {
    console.log(signal + " received. Shutting down gracefully...");

    server.close(async () => {
      try {
        await mongoose.connection.close();
        console.log("Database connection closed.");
      } catch (error) {
        console.error("Error closing database:", error);
      }

      process.exit(0);
    });

    setTimeout(() => {
      console.error("Forced shutdown after timeout.");
      process.exit(1);
    }, 10000).unref();
  }

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

startServer();
