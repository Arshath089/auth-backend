const express = require('express');
const { CheckUser } = require("../controllers/login");
const { InsertVerifyUser, InsertSignUpUser } = require('../controllers/signin');
var router = express.Router();


router.get("/:token", async(req, res) => {
    try {
        const response = await InsertSignUpUser(req.params.token);
        res.status(200).send(response);
    } catch (error) {
        console.log(error);
        res.status(500).send(`<html>
        <body>
        <h4>Registration Successful</h4>
        <p>Unexpected Error happened</p>
        <p>With regards</p>
        <p>Team</p>
        </body>
        </html>`);
    }
})

router.post("/verify", async(req, res) => {
    try {
        const {name, email, password} = await req.body;
    console.log(name, email, password);
    const registerCredentials = await CheckUser(email);
    if(registerCredentials === false) {
        await InsertVerifyUser(name, email, password);
        res.status(200).send(true)
    } else if(registerCredentials === true) {
        res.status(200).send(false)

    } else if(registerCredentials === "Server Busy"){
        res.status(500).send("Server Busy");
    }
    } catch (error) {
        console.log(error);
    }
})

module.exports = router;