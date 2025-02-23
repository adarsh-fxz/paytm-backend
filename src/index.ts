import express from "express";
import dotenv from "dotenv";
import router from "./routes/index";
import cors from "cors";
import mongoose from "mongoose";


dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;
const DB_URL = process.env.DB_URL;

app.use(express.json());
app.use(cors());

app.use('/api/v1', router);

async function main() {
    await mongoose.connect(DB_URL as string);
    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}

main()