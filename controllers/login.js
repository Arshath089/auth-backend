const User = require("../models/User")
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const client = require("../redis");
const jwt = require("jsonwebtoken");

dotenv.config();


async function CheckUser(email) {
    try {
        const user = await User.findOne({ email:email })
        if(user) {
            return true;
        } else {
            return false;
        }
    } catch (error) {
        return "Server Busy";
    }
}

async function AuthenticateUser(email, password) {
    try {
        const userCheck = await User.findOne({ email:email });
        const validPassword = await bcrypt.compare(password, userCheck.password);
        if(validPassword) {
            const token = jwt.sign({email}, process.env.login_secret_token);
            const response = {
                id: userCheck._id,
                name: userCheck.name,
                email: userCheck.email,
                token: userCheck.token,
                status: true,
            }
            await client.set(`key-${email}`,JSON.stringify(response))
            await User.findOneAndUpdate({ email: userCheck.email }, { $set:{token:token }}, { new:true });
            return response;
        }
        return "Invalid User name or password";
    } catch (error) {
        console.log(error);
        return "Server Busy";
    }
}

async function AuthorizeUser(token) {
    try {
        const decodedToken = jwt.verify(token, process.env.login_secret_token);
        if(decodedToken) {
            const email = decodedToken.email;
            const auth = await client.get(`key-${email}`);
            if(auth) {
                const data = JSON.parse(auth);
                return data;
            } else {
                const data = await User.findOne({ email: email });
                return data;
            }
        }
        return false;
    } catch (error) {
        console.log(error);
    }
}

module.exports = { CheckUser, AuthenticateUser,AuthorizeUser };