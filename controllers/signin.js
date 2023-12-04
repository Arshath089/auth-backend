const User = require("../models/User")
const { sendMail } = require("./SendMail")
const bcrypt = require("bcrypt")
const mongoose = require("mongoose")
const jwt = require("jsonwebtoken")
const verifyUser = require("../models/verifyUser");
const dotenv = require("dotenv")
dotenv.config();


async function InsertVerifyUser(name, email, password) {
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const token = generateToken(email);

        const newUser = new verifyUser({
            name: name,
            email: email,
            password: hashedPassword,
            token: token,
        });

        const activationLink = `http://localhost:4000/signin/${token}`;
        const content = `<h4>Hi, there</h4>
        <h5>Welcome to the app</h5>
        <p>thank you for signing up</p>
        <a href="${activationLink}">Click here</a>
        <p>With regards</p>
        <p>Team</p>`;

        await newUser.save();
        sendMail(email,"VerifyUser",content);

    } catch (error) {
        console.log(error);
    }
}


function generateToken(email) {
    const token = jwt.sign(email, process.env.signup_Secret_Token);
    return token;

}


async function InsertSignUpUser(token) {
    try {
        const userVerify = await verifyUser.findOne({ token:token });
    if(userVerify) {
        const newUser = new User({
            name: userVerify.name,
            email: userVerify.email,
            password: userVerify.password,
            forgetPassword: {},
        });

        await newUser.save();
        await userVerify.deleteOne({ token:token });
        const content = `<h4>Registration Successful</h4>
        <h5>Welcome to the app</h5>
        <p>You are successfully registered</p>
        <p>With regards</p>
        <p>Team</p>`;
        sendMail(newUser.email,"Registration Successfull", content);
        return `<h4>Registration Successful</h4>
        <h5>Welcome to the app</h5>
        <p>You are successfully registered</p>
        <p>With regards</p>
        <p>Team</p>`;
    }
    return `<h4>Registration Successful</h4>
        <p>Link Expired ...............</p>
        <p>With regards</p>
        <p>Team</p>`;
    } catch (error) {
        console.log(error);
        return `<html>
        <body>
        <h4>Registration Successful</h4>
        <p>Unexpected Error happened</p>
        <p>With regards</p>
        <p>Team</p>
        </body>
        </html>`;
    }
}

module.exports = { InsertVerifyUser,InsertSignUpUser };