import express, { Request, Response } from "express";
import verifyToken from "../middleware";
import { Account } from "../db";
import mongoose from "mongoose";

const router = express.Router();

interface CustomRequest extends Request {
    userId?: string;
}

router.get('/balance', verifyToken, async (req: CustomRequest, res: Response): Promise<void> => {
    try {
        const account = await Account.findOne({ userId: req.userId });
        if (!account) {
            res.status(404).json({ message: "Account not found" });
            return;
        }
        res.json({ balance: account.balance });
    } catch (error) {
        res.status(500).json({ message: "Internal server error" });
    }
});

router.post('/transfer', verifyToken, async (req: CustomRequest, res: Response): Promise<void> => {
    const session = await mongoose.startSession();
    try {
        session.startTransaction();
        const { amount, to } = req.body;

        if (req.userId === to) {
            await session.abortTransaction();
            res.status(400).json({ message: "Cannot transfer money to yourself" });
            return;
        }

        const account = await Account.findOne({ userId: req.userId }).session(session);

        if (!account || account.balance < amount) {
            await session.abortTransaction();
            res.status(400).json({ message: "Insufficient balance" });
            return;
        }

        const toAccount = await Account.findOne({ userId: to }).session(session);

        if (!toAccount) {
            await session.abortTransaction();
            res.status(404).json({ message: "Receiver account not found" });
            return;
        }

        await Account.updateOne({ userId: req.userId }, { $inc: { balance: -amount } }).session(session);
        await Account.updateOne({ userId: to }, { $inc: { balance: amount } }).session(session);

        await session.commitTransaction();
        res.json({ message: "Transfer successful" });

    } catch (error) {
        res.status(500).json({ message: "Internal server error" });
    } finally {
        await session.endSession();
    }
});

export default router;