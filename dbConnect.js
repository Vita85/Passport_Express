const { MongoClient } = require("mongodb");
require("dotenv").config();

const mongoInstance = {
  client: new MongoClient(process.env.MONGO_URI),
  database: null,

  async connectDB() {
    try {
      await this.client.connect();
      console.log("Connected to MongoDB");

      this.database = this.client.db("sample_mflix");
    } catch (error) {
      console.log("Error connecting to MongoDB", error);
      throw error;
    }
  },

  getDB() {
    if (!this.database) {
      throw new Error("Not connected to the database");
    }
    return this.database;
  },
};

module.exports = { mongoInstance };
