import express, { Request, Response } from "express";
import User from "../db";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { z } from "zod";

const router = express.Router();

// Define Zod schema for request validation
const signupBody = z.object({
    username: z.string().email(),
    firstName: z.string().min(2).max(20),
    lastName: z.string().min(2).max(20),
    password: z.string().min(6).max(20)
});

router.post('/signup', async (req: Request, res: Response): Promise<void> => {
    try {
        // Validate request body
        const parsedBody = signupBody.safeParse(req.body);
        if (!parsedBody.success) {
            res.status(400).json({ message: "Incorrect inputs" });
            return;
        }

        const { username, password, firstName, lastName } = parsedBody.data;

        // Check if user already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            res.status(409).json({ message: "Email already taken" });
            return;
        }

        // Hash password with bcrypt (salt rounds = 5)
        const hashedPassword = await bcrypt.hash(password, 5);

        // Create new user
        const user = await User.create({
            username,
            password: hashedPassword,
            firstName,
            lastName
        });

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET as string,
            { expiresIn: "1h" }
        );

        res.status(201).json({
            message: "User created successfully",
            token
        });
    } catch (error) {
        console.error("Signup error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

const signinBody = z.object({
    username: z.string().email(),
    password: z.string().min(6).max(20)
});

router.post('/signin', async (req: Request, res: Response): Promise<void> => {
    try {
        // Validate request body
        const parsedBody = signinBody.safeParse(req.body);
        if (!parsedBody.success) {
            res.status(400).json({ message: "Incorrect inputs" });
            return;
        }

        const { username, password } = parsedBody.data;

        // Check if user exists
        const user = await User.findOne({ username });
        if (!user) {
            res.status(401).json({ message: "Email not found" });
            return;
        }

        // Compare password with hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            res.status(401).json({ message: "Incorrect password" });
            return;
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET as string,
            { expiresIn: "1h" }
        );

        res.status(200).json({
            message: "Signin successful",
            token
        });
    } catch (error) {
        console.error("Signin error:", error);
        res.status(500).json({ message: "Error while signing in" });
    }
});

export default router;
