const express = require('express');
const { AuthenticateUser } = require('../controllers/login');
const client = require("../redis");
var router = express.Router();

client
    .connect()
    .then(() => {
        console.log("connected to redis");
    })
    .catch((e) => {
        console.log(e);
    });

router.post("/",async (req,res) => {
    const { email, password } = await req.body;
    var loginCredentials = await AuthenticateUser(email, password);
    console.log(loginCredentials);
    if(loginCredentials === "Invalid User name or password") {
        res.status(200).send("Invalid User name or password");
    } else if(loginCredentials === "Server Busy") {
        res.status(200).send("Server Busy");
    } else {
        res.status(200).json({ token: loginCredentials.token });
    }
});


module.exports = router;