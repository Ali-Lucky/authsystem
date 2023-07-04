require("dotenv").config();
require('./config/database').connect();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const User = require('./models/user');
const auth = require('./middlewares/auth');

const app = express();
app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
    res.send("<h1>Hello world</h1>");
});

app.post("/register", async (req, res) => {
    try {
        const { firstname, lastname, email, password } = req.body;

        if (!(email && password && firstname && lastname)) {
            res.status(400).send('All fields are required');
        };
    
        const existingUser = await User.findOne({ email });
    
        if (existingUser) {
            res.status(400).send("User already exist");
        };
    
        const encryptPassword = await bcrypt.hash(password, 10);
    
        const user = await User.create({
            firstname,
            lastname,
            email: email.toLowerCase(),
            password: encryptPassword
        });
    
        const token = jwt.sign(
            {
                userId: user._id,
                email
            },
            process.env.SECRET_KEY,
            {
                expiresIn: "2h"
            }
        );
    
        user.token = token;
        user.password = undefined;
    
        res.status(201).json(user)
    } catch (error) {
        console.log(error);
    };
});

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!(email && password)) {
            res.status(400).send("Email and Password are mandatory");
        };

        const user = await User.findOne({ email });

        if (user && (await bcrypt.compare(password, user.password))) {
            const token = jwt.sign(
                { userId: user._id, email },
                process.env.SECRET_KEY,
                {
                    expiresIn: "2h"
                }
            )
            user.token = token;
            user.password = undefined;
            // res.status(200).json(user);
            const options = {
                expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
                httpOnly: true
            };
            res.status(200).cookie('token', token, options).json({ success: true, token, user });
        };

        res.sendStatus(400).send("email or password is incorrect");

    } catch (error) {
        console.log(error);
    };
});

app.get("/dashboard", auth, (req, res) => {
    try {
        res.send("Some secret information");

    } catch (error) {
        console.log();
    };
});

module.exports = app;